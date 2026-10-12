#define _GNU_SOURCE
/*
 * symtrace - attach to a running process by PID and count every call to a
 * function identified by its symbol name.
 *
 * Usage: symtrace <pid> <symbol>
 *
 * Mechanism (x86_64, no code injection):
 *   1. PTRACE_ATTACH the target.
 *   2. Enumerate loaded modules from /proc/<pid>/maps.
 *   3. For each module, parse its ELF file and find every dynamic
 *      relocation (JUMP_SLOT / GLOB_DAT) that refers to <symbol>; each
 *      gives the address of one GOT slot in the live process.
 *   4. Resolve the real address of the function (from a GOT slot that is
 *      already resolved, or from the defining module's symbol table).
 *   5. Overwrite every GOT slot with a distinct "magic" unmapped address
 *      (via PTRACE_POKEDATA, which ignores write permissions, so RELRO
 *      is not an issue).
 *   6. On every SIGSEGV stop whose RIP is a magic address, bump the call
 *      counter, redirect RIP to the real function and continue.
 *   7. On exit (Ctrl-C or target termination) restore the original GOT
 *      values, detach and print the summary.
 *
 * Limitations: only x86_64 targets; calls made internally within the
 * defining library that do not cross a PLT/GOT are not seen.
 */

#include "elfparse.h"
#include "prototypes.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_MODULES 512
#define MAX_SLOTS 4096
#define MAGIC_BASE 0x700000000000ULL
#define MAGIC_STRIDE 16

struct module {
    char path[PATH_MAX];
    uint64_t base;
};

struct slot {
    uint64_t addr;
    uint64_t orig;
};

static struct module modules[MAX_MODULES];
static int nmodules;
static struct slot slots[MAX_SLOTS];
static int nslots;
static uint64_t real_addr;
static uint64_t call_count;
static volatile sig_atomic_t interrupted;
static pid_t target_pid;
static const char *traced_symbol;
static const enum arg_type *proto_args;

static bool read_mem(pid_t pid, uint64_t addr, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        size_t chunk = len - done;
        size_t align = addr % sizeof(long);
        if (align || chunk < sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr - align), NULL);
            if (errno)
                return false;
            size_t n = sizeof(long) - align;
            if (n > chunk)
                n = chunk;
            memcpy((char *)buf + done, (char *)&word + align, n);
            done += n;
            addr += n;
            continue;
        }
        size_t nwords = chunk / sizeof(long);
        for (size_t i = 0; i < nwords; i++) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * sizeof(long)), NULL);
            if (errno)
                return false;
            memcpy((char *)buf + done + i * sizeof(long), &word, sizeof(long));
        }
        done += nwords * sizeof(long);
        addr += nwords * sizeof(long);
    }
    return true;
}

static bool read_cstring(pid_t pid, uint64_t addr, char *buf, size_t bufsz)
{
    if (addr == 0 || addr == UINT64_MAX) {
        buf[0] = '\0';
        return addr != 0;
    }
    size_t total = 0;
    while (total < bufsz - 1) {
        size_t chunk = bufsz - 1 - total;
        if (chunk > 64)
            chunk = 64;
        if (!read_mem(pid, addr + total, buf + total, chunk)) {
            buf[total] = '\0';
            return total > 0;
        }
        for (size_t i = 0; i < chunk; i++) {
            if (buf[total + i] == '\0')
                return true;
        }
        total += chunk;
    }
    buf[bufsz - 1] = '\0';
    return true;
}

static void print_escaped(const char *s)
{
    putchar('"');
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\')
            printf("\\%c", c);
        else if (c >= 0x20 && c < 0x7f)
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    putchar('"');
}

static void print_call_args(pid_t pid, const struct user_regs_struct *regs)
{
    uint64_t int_args[6] = {
        regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9
    };
    unsigned long long sse_args[8] = { 0 };
    struct user_fpregs_struct fp;
    if (ptrace(PTRACE_GETFPREGS, pid, NULL, &fp) == 0) {
        memcpy(sse_args, fp.xmm_space, sizeof(sse_args));
    }

    int int_idx = 0;
    int sse_idx = 0;
    int stack_idx = 0;

    printf("%s(", traced_symbol);
    if (!proto_args) {
        printf("rdi=%#llx rsi=%#llx rdx=%#llx rcx=%#llx r8=%#llx r9=%#llx",
               (unsigned long long)int_args[0], (unsigned long long)int_args[1],
               (unsigned long long)int_args[2], (unsigned long long)int_args[3],
               (unsigned long long)int_args[4], (unsigned long long)int_args[5]);
        printf(")\n");
        return;
    }

    bool first = true;
    for (int a = 0; proto_args[a] != TYPE_END; a++) {
        if (!first)
            printf(", ");
        first = false;

        enum arg_type t = proto_args[a];
        uint64_t v = 0;
        double d = 0;
        bool is_sse = false;

        if (t == TYPE_FLOAT || t == TYPE_DOUBLE) {
            if (sse_idx < 8) {
                unsigned long long raw = sse_args[sse_idx];
                if (t == TYPE_DOUBLE) {
                    memcpy(&d, &raw, sizeof(d));
                } else {
                    float f;
                    memcpy(&f, &raw, sizeof(f));
                    d = (double)f;
                }
                is_sse = true;
            }
            sse_idx++;
        } else {
            if (int_idx < 6) {
                v = int_args[int_idx];
            } else {
                uint64_t sp = regs->rsp + 8 + (uint64_t)stack_idx * 8;
                read_mem(pid, sp, &v, sizeof(v));
                stack_idx++;
            }
            int_idx++;
        }

        switch (t) {
        case TYPE_INTEGER:
            printf("%lld", (long long)(int64_t)v);
            break;
        case TYPE_UNSIGNED:
            printf("%lu", (unsigned long)v);
            break;
        case TYPE_CHAR:
            printf("'%c'", (char)v);
            break;
        case TYPE_POINTER:
            printf("%#lx", (unsigned long)v);
            break;
        case TYPE_STRING: {
            char buf[65];
            if (read_cstring(pid, v, buf, sizeof(buf)))
                print_escaped(buf);
            else if (v == 0)
                printf("NULL");
            else
                printf("%#lx", (unsigned long)v);
            break;
        }
        case TYPE_DOUBLE:
        case TYPE_FLOAT:
            if (is_sse)
                printf("%g", d);
            else
                printf("<?>");
            break;
        default:
            printf("<?>");
            break;
        }
    }
    printf(")\n");
}

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void on_sigint(int sig)
{
    (void)sig;
    interrupted = 1;
}


static uint64_t peek(pid_t pid, uint64_t addr)
{
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (errno)
        return UINT64_MAX;
    return (uint64_t)v;
}

static int poke(pid_t pid, uint64_t addr, uint64_t val)
{
    return ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)val);
}

static size_t vaddr_off(const struct elf_file *e, uint64_t vaddr)
{
    for (int i = 0; i < e->eh64->e_phnum; i++) {
        Elf64_Phdr *ph =
            (Elf64_Phdr *)(e->base + e->eh64->e_phoff + i * e->eh64->e_phentsize);
        if (ph->p_type == PT_LOAD && vaddr >= ph->p_vaddr &&
            vaddr < ph->p_vaddr + ph->p_filesz)
            return (size_t)(vaddr - ph->p_vaddr + ph->p_offset);
    }
    return 0;
}

static void load_maps(pid_t pid)
{
    char mapsfile[64];
    snprintf(mapsfile, sizeof(mapsfile), "/proc/%d/maps", pid);
    FILE *f = fopen(mapsfile, "r");
    if (!f)
        die("symtrace: cannot open %s: %s", mapsfile, strerror(errno));

    char line[PATH_MAX + 128];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end, off;
        char perms[8];
        char path[PATH_MAX];
        path[0] = '\0';
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095s",
                       &start, &end, perms, &off, path);
        (void)end;
        if (n < 4)
            continue;
        if (path[0] != '/')
            continue;
        if (off != 0)
            continue;

        char *bang = strstr(path, " (deleted");
        if (bang)
            *bang = '\0';

        int existing = -1;
        for (int i = 0; i < nmodules; i++)
            if (strcmp(modules[i].path, path) == 0) {
                existing = i;
                break;
            }
        if (existing >= 0) {
            if (start < modules[existing].base)
                modules[existing].base = start;
            continue;
        }
        if (nmodules >= MAX_MODULES)
            break;
        snprintf(modules[nmodules].path, sizeof(modules[0].path), "%s", path);
        modules[nmodules].base = start;
        nmodules++;
    }
    fclose(f);
}

static bool is_target_reloc_type(uint64_t type)
{
#if defined(ELF_MACHINE_X86_64) || defined(__x86_64__)
    return type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT;
#else
    (void)type;
    return false;
#endif
}

static void find_got_slots(const struct elf_file *e, uint64_t base,
                           const char *symbol)
{
    if (!e->is64)
        return;

    struct { uint64_t addr; uint64_t size; } tables[2] = {
        { e->jmprel, e->pltrelsz },
        { e->rela, e->relasz },
    };

    for (int t = 0; t < 2; t++) {
        if (!tables[t].addr || !tables[t].size)
            continue;
        size_t off = vaddr_off(e, tables[t].addr);
        if (!off)
            continue;
        size_t entsz = sizeof(Elf64_Rela);
        size_t count = tables[t].size / entsz;
        for (size_t i = 0; i < count; i++) {
            Elf64_Rela *r = (Elf64_Rela *)(e->base + off + i * entsz);
            uint64_t symidx = ELF64_R_SYM(r->r_info);
            uint64_t type = ELF64_R_TYPE(r->r_info);
            if (!is_target_reloc_type(type))
                continue;
            const char *name = elf_sym_name(e, symidx);
            if (!name || strcmp(name, symbol) != 0)
                continue;
            uint64_t slotaddr = base + r->r_offset;
            bool dup = false;
            for (int s = 0; s < nslots; s++)
                if (slots[s].addr == slotaddr) {
                    dup = true;
                    break;
                }
            if (dup || nslots >= MAX_SLOTS)
                continue;
            slots[nslots].addr = slotaddr;
            slots[nslots].orig = 0;
            nslots++;
        }
    }
}

static uint64_t resolve_real_addr(pid_t pid, const char *symbol)
{
    for (int i = 0; i < nmodules; i++) {
        struct elf_file e;
        if (!elf_load_file(&e, modules[i].path))
            continue;
        for (size_t s = 0; s < elf_sym_count(&e); s++) {
            const char *n = elf_sym_name(&e, s);
            if (n && strcmp(n, symbol) == 0 && elf_sym_defined(&e, s)) {
                uint64_t v = elf_sym_value(&e, s);
                elf_unload(&e);
                if (v)
                    return modules[i].base + v;
                return 0;
            }
        }
        elf_unload(&e);
    }
    for (int s = 0; s < nslots; s++) {
        uint64_t v = peek(pid, slots[s].addr);
        if (v != UINT64_MAX && v && (v & 0xfff) != 0x000)
            return v;
    }
    return 0;
}

static bool range_mapped(pid_t pid, uint64_t addr)
{
    char mapsfile[64];
    snprintf(mapsfile, sizeof(mapsfile), "/proc/%d/maps", pid);
    FILE *f = fopen(mapsfile, "r");
    if (!f)
        return true;
    char line[512];
    bool mapped = false;
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2 &&
            addr >= start && addr < end) {
            mapped = true;
            break;
        }
    }
    fclose(f);
    return mapped;
}

static void restore_and_detach(pid_t pid)
{
    for (int i = 0; i < nslots; i++)
        if (slots[i].orig)
            poke(pid, slots[i].addr, slots[i].orig);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <symbol>\n", argv[0]);
        fprintf(stderr, "Attaches to <pid> and counts calls to <symbol>.\n");
        fprintf(stderr, "Press Ctrl-C to stop and print the summary.\n");
        return 2;
    }

    target_pid = (pid_t)atoi(argv[1]);
    const char *symbol = argv[2];
    traced_symbol = symbol;
    proto_args = proto_lookup(symbol);
    if (target_pid <= 0)
        die("symtrace: invalid pid '%s'", argv[1]);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0)
        die("symtrace: cannot attach to %d: %s", target_pid, strerror(errno));
    if (waitpid(target_pid, NULL, 0) < 0)
        die("symtrace: waitpid: %s", strerror(errno));

    load_maps(target_pid);

    for (int i = 0; i < nmodules; i++) {
        struct elf_file e;
        if (!elf_load_file(&e, modules[i].path))
            continue;
        find_got_slots(&e, modules[i].base, symbol);
        elf_unload(&e);
    }

    if (nslots == 0) {
        fprintf(stderr, "symtrace: no GOT slot for '%s' in %d\n",
                symbol, target_pid);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }

    real_addr = resolve_real_addr(target_pid, symbol);
    if (!real_addr || !range_mapped(target_pid, real_addr)) {
        fprintf(stderr,
                "symtrace: cannot resolve real address of '%s' in %d\n",
                symbol, target_pid);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }

    for (int i = 0; i < nslots; i++) {
        uint64_t orig = peek(target_pid, slots[i].addr);
        if (orig == UINT64_MAX) {
            fprintf(stderr, "symtrace: cannot read GOT slot at %#lx\n",
                    (unsigned long)slots[i].addr);
            continue;
        }
        slots[i].orig = orig;
        uint64_t magic = MAGIC_BASE + (uint64_t)i * MAGIC_STRIDE;
        if (poke(target_pid, slots[i].addr, magic) < 0)
            fprintf(stderr, "symtrace: cannot patch GOT slot at %#lx: %s\n",
                    (unsigned long)slots[i].addr, strerror(errno));
    }

    printf("symtrace: tracing '%s' in pid %d (%d GOT slot%s) - press Ctrl-C to stop\n",
           symbol, target_pid, nslots, nslots > 1 ? "s" : "");
    fflush(stdout);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) < 0) {
        restore_and_detach(target_pid);
        die("symtrace: PTRACE_CONT: %s", strerror(errno));
    }

    int status;
    while (!interrupted) {
        pid_t r = waitpid(target_pid, &status, __WALL);
        if (r < 0) {
            if (errno == EINTR) {
                if (interrupted)
                    break;
                continue;
            }
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            interrupted = 1;
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;
        int sig = WSTOPSIG(status);
        if (sig == SIGSEGV) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == 0) {
                uint64_t retaddr = regs.rax;
                (void)retaddr;
                bool is_magic = false;
                if (regs.rip >= MAGIC_BASE &&
                    regs.rip < MAGIC_BASE + (uint64_t)nslots * MAGIC_STRIDE) {
                    is_magic = true;
                }
                if (is_magic) {
                    call_count++;
                    print_call_args(target_pid, &regs);
                    fflush(stdout);
                    regs.rip = real_addr;
                    ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
                    ptrace(PTRACE_CONT, target_pid, NULL, NULL);
                    continue;
                }
            }
            ptrace(PTRACE_CONT, target_pid, NULL, (void *)(long)sig);
            continue;
        }
        ptrace(PTRACE_CONT, target_pid, NULL,
               sig == SIGTRAP ? NULL : (void *)(long)sig);
    }

    kill(target_pid, SIGSTOP);
    waitpid(target_pid, NULL, __WALL);
    restore_and_detach(target_pid);

    printf("%s: %lu call%s intercepted\n", symbol,
           (unsigned long)call_count, call_count == 1 ? "" : "s");
    return 0;
}
