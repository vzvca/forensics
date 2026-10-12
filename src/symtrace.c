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
#include "dwarg.h"

#include <dirent.h>
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
#define MAGIC_RET_BASE 0x710000000000ULL
#define MAX_PENDING 256
#define ARGBUF_LEN 512

struct module {
    char path[PATH_MAX];
    uint64_t base;
};

struct slot {
    uint64_t addr;
    uint64_t orig;
    const char *symbol;
    uint64_t real_addr;
    const struct func_prototype *proto;   /* hard-coded table */
    struct func_prototype dw;             /* from DWARF, dw.name==NULL if none */
    char pretty[256];
    uint64_t calls;
};

struct pending_call {
    bool used;
    int slot_idx;
    uint64_t magic_ret;
    uint64_t real_retaddr;
    char args[ARGBUF_LEN];
};

static struct module modules[MAX_MODULES];
static int nmodules;
static struct slot slots[MAX_SLOTS];
static int nslots;
static char symbol_buf[8][64];
static const char *symbols[8];
static int nsymbols;

static bool dwarf_into(struct func_prototype *out, char pretty[256],
                       const char *elf_path, const char *symbol)
{
    enum arg_type args[8];
    enum ret_type ret;
    char prettybuf[256];

    if (dwarf_func_prototype(elf_path, symbol, args, &ret, prettybuf)) {
        memset(out, 0, sizeof(*out));
        out->name = symbol;
        out->ret = ret;
        for (int i = 0; i < 8; i++)
            out->args[i] = args[i];
        snprintf(pretty, 256, "%s", prettybuf);
        return true;
    }
    return false;
}

static bool try_dwarf_proto(struct func_prototype *out, char pretty[256],
                            const char *elf_path, const char *symbol)
{
    if (dwarf_into(out, pretty, elf_path, symbol))
        return true;

    uint32_t crc;
    char *link = dwarf_debuglink(elf_path, &crc);
    if (!link)
        return false;

    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", elf_path);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    else
        strcpy(dir, ".");

    const char *suffixes[] = { "%s/%s", "%s/.debug/%s", "/usr/lib/debug%s/%s", NULL };
    for (int i = 0; suffixes[i]; i++) {
        char cand[PATH_MAX];
        snprintf(cand, sizeof(cand), suffixes[i], dir, link);
        if (access(cand, R_OK) == 0 &&
            dwarf_into(out, pretty, cand, symbol)) {
            free(link);
            return true;
        }
    }
    free(link);
    return false;
}

static volatile sig_atomic_t interrupted;
static pid_t target_pid;
static struct pending_call pending[MAX_PENDING];

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

static void print_call_args(pid_t pid, const struct user_regs_struct *regs,
                            const char *name, const struct func_prototype *proto,
                            char *out, size_t outsz)
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

    size_t pos = 0;
    int n = snprintf(out + pos, outsz - pos, "%s(", name);
    if (n < 0 || (size_t)n >= outsz - pos)
        return;
    pos += (size_t)n;

    if (!proto || proto->ret == RET_NONE) {
    }
    if (!proto) {
        n = snprintf(out + pos, outsz - pos,
                     "rdi=%#llx rsi=%#llx rdx=%#llx rcx=%#llx r8=%#llx r9=%#llx",
                     (unsigned long long)int_args[0], (unsigned long long)int_args[1],
                     (unsigned long long)int_args[2], (unsigned long long)int_args[3],
                     (unsigned long long)int_args[4], (unsigned long long)int_args[5]);
        if (n < 0 || (size_t)n >= outsz - pos)
            return;
        pos += (size_t)n;
        snprintf(out + pos, outsz - pos, ")");
        return;
    }

    bool first = true;
    for (int a = 0; proto->args[a] != TYPE_END; a++) {
        if (!first) {
            n = snprintf(out + pos, outsz - pos, ", ");
            if (n < 0 || (size_t)n >= outsz - pos)
                return;
            pos += (size_t)n;
        }
        first = false;

        enum arg_type t = proto->args[a];
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

        char piece[96];
        switch (t) {
        case TYPE_INTEGER:
            n = snprintf(piece, sizeof(piece), "%lld", (long long)(int64_t)v);
            break;
        case TYPE_UNSIGNED:
            n = snprintf(piece, sizeof(piece), "%lu", (unsigned long)v);
            break;
        case TYPE_CHAR:
            n = snprintf(piece, sizeof(piece), "'%c'", (char)v);
            break;
        case TYPE_POINTER:
            n = snprintf(piece, sizeof(piece), "%#lx", (unsigned long)v);
            break;
        case TYPE_STRING: {
            char buf[65];
            piece[0] = '\0';
            if (read_cstring(pid, v, buf, sizeof(buf))) {
                size_t w = 0;
                w += (size_t)snprintf(piece, sizeof(piece), "\"");
                for (const char *p = buf; *p && w + 8 < sizeof(piece); p++) {
                    unsigned char c = (unsigned char)*p;
                    if (c == '"' || c == '\\') {
                        w += (size_t)snprintf(piece + w, sizeof(piece) - w, "\\%c", c);
                    } else if (c >= 0x20 && c < 0x7f) {
                        piece[w++] = (char)c;
                        piece[w] = '\0';
                    } else {
                        w += (size_t)snprintf(piece + w, sizeof(piece) - w, "\\x%02x", c);
                    }
                }
                snprintf(piece + w, sizeof(piece) - w, "\"");
            } else if (v == 0) {
                snprintf(piece, sizeof(piece), "NULL");
            } else {
                snprintf(piece, sizeof(piece), "%#lx", (unsigned long)v);
            }
            n = (int)strlen(piece);
            break;
        }
        case TYPE_DOUBLE:
        case TYPE_FLOAT:
            if (is_sse)
                n = snprintf(piece, sizeof(piece), "%g", d);
            else
                n = snprintf(piece, sizeof(piece), "<?>");
            break;
        default:
            n = snprintf(piece, sizeof(piece), "<?>");
            break;
        }
        if (n < 0)
            return;
        if ((size_t)n >= outsz - pos)
            return;
        memcpy(out + pos, piece, (size_t)n + 1);
        pos += (size_t)n;
    }
    snprintf(out + pos, outsz - pos, ")");
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

static void find_got_slots(const struct elf_file *e, uint64_t base)
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
            if (!name)
                continue;
            const char *matched = NULL;
            for (int k = 0; k < nsymbols; k++)
                if (strcmp(name, symbols[k]) == 0) {
                    matched = symbols[k];
                    break;
                }
            if (!matched)
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
            memset(&slots[nslots], 0, sizeof(slots[nslots]));
            slots[nslots].addr = slotaddr;
            slots[nslots].symbol = matched;
            nslots++;
        }
    }
}

static char defining_module[PATH_MAX];

static bool setup_slots(pid_t pid, bool fatal);

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
                if (v) {
                    snprintf(defining_module, sizeof(defining_module), "%s",
                             modules[i].path);
                    return modules[i].base + v;
                }
                return 0;
            }
        }
        elf_unload(&e);
    }
    for (int s = 0; s < nslots; s++) {
        if (slots[s].orig)
            continue; /* already patched with a magic address */
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

#define MAX_THREADS 256
static pid_t threads[MAX_THREADS];
static int nthreads;

static void restore_and_detach(pid_t pid)
{
    (void)pid;
    for (int i = 0; i < nslots; i++)
        if (slots[i].orig)
            poke(target_pid, slots[i].addr, slots[i].orig);
    for (int t = 0; t < nthreads; t++)
        ptrace(PTRACE_DETACH, threads[t], NULL, NULL);
}

static bool child_launched;

static void attach_all_threads(pid_t pid)
{
    char taskdir[64];
    snprintf(taskdir, sizeof(taskdir), "/proc/%d/task", pid);
    DIR *d = opendir(taskdir);
    if (!d)
        die("symtrace: cannot open %s: %s", taskdir, strerror(errno));
    struct dirent *ent;
    nthreads = 0;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;
        pid_t tid = (pid_t)atoi(ent->d_name);
        if (nthreads >= MAX_THREADS)
            break;
        if (child_launched) {
            threads[nthreads++] = tid;
            continue;
        }
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
            fprintf(stderr, "symtrace: cannot attach to thread %d: %s\n",
                    tid, strerror(errno));
            continue;
        }
        threads[nthreads++] = tid;
    }
    closedir(d);
    if (nthreads == 0)
        die("symtrace: could not attach to any thread of %d", pid);
    if (child_launched)
        return;
    for (int t = 0; t < nthreads; t++) {
        int status;
        pid_t r;
        do {
            r = waitpid(threads[t], &status, __WALL);
        } while (r < 0 && errno == EINTR);
        if (r != threads[t]) {
            fprintf(stderr, "symtrace: waitpid for thread %d failed\n",
                    threads[t]);
            continue;
        }
        if (ptrace(PTRACE_SETOPTIONS, threads[t], NULL,
                   (void *)(long)PTRACE_O_TRACECLONE) < 0)
            fprintf(stderr, "symtrace: cannot set options on thread %d: %s\n",
                    threads[t], strerror(errno));
    }
}

static struct pending_call *pending_alloc(void)
{
    for (int i = 0; i < MAX_PENDING; i++)
        if (!pending[i].used) {
            memset(&pending[i], 0, sizeof(pending[i]));
            pending[i].used = true;
            return &pending[i];
        }
    return NULL;
}

static struct pending_call *pending_find(uint64_t magic_ret)
{
    for (int i = 0; i < MAX_PENDING; i++)
        if (pending[i].used && pending[i].magic_ret == magic_ret)
            return &pending[i];
    return NULL;
}

static void handle_call_stop(pid_t tid, struct user_regs_struct *regs, int sidx)
{
    struct slot *sl = &slots[sidx];

    sl->calls++;

    struct pending_call *pc = pending_alloc();
    if (!pc) {
        char tmp[ARGBUF_LEN];
        print_call_args(tid, regs, sl->symbol, sl->proto, tmp, sizeof(tmp));
        printf("%s\n", tmp);
        fflush(stdout);
        regs->rip = sl->real_addr;
        ptrace(PTRACE_SETREGS, tid, NULL, regs);
        ptrace(PTRACE_CONT, tid, NULL, NULL);
        return;
    }
    pc->slot_idx = sidx;

    print_call_args(tid, regs, sl->symbol, sl->proto, pc->args, sizeof(pc->args));

    uint64_t retaddr = peek(tid, regs->rsp);
    if (retaddr == UINT64_MAX) {
        printf("%s\n", pc->args);
        fflush(stdout);
        pc->used = false;
        regs->rip = sl->real_addr;
        ptrace(PTRACE_SETREGS, tid, NULL, regs);
        ptrace(PTRACE_CONT, tid, NULL, NULL);
        return;
    }

    int idx = -1;
    for (int i = 0; i < MAX_PENDING; i++)
        if (&pending[i] == pc) {
            idx = i;
            break;
        }
    pc->magic_ret = MAGIC_RET_BASE + (uint64_t)idx * MAGIC_STRIDE;
    pc->real_retaddr = retaddr;

    if (poke(tid, regs->rsp, pc->magic_ret) < 0) {
        printf("%s\n", pc->args);
        fflush(stdout);
        pc->used = false;
        regs->rip = sl->real_addr;
        ptrace(PTRACE_SETREGS, tid, NULL, regs);
        ptrace(PTRACE_CONT, tid, NULL, NULL);
        return;
    }

    regs->rip = sl->real_addr;
    ptrace(PTRACE_SETREGS, tid, NULL, regs);
    ptrace(PTRACE_CONT, tid, NULL, NULL);
}

static void handle_return_stop(pid_t tid, struct user_regs_struct *regs)
{
    struct pending_call *pc = pending_find(regs->rip);
    if (!pc) {
        ptrace(PTRACE_CONT, tid, NULL, NULL);
        return;
    }
    struct slot *sl = &slots[pc->slot_idx];
    const struct func_prototype *proto = sl->proto;

    char retbuf[96];
    unsigned long long rax = regs->rax;

    bool have_ret = proto && proto->ret != RET_NONE;
    if (have_ret) {
        switch (proto->ret) {
        case RET_INT:
            snprintf(retbuf, sizeof(retbuf), " = %lld", (long long)(int64_t)rax);
            break;
        case RET_UNSIGNED:
            snprintf(retbuf, sizeof(retbuf), " = %lu", (unsigned long)rax);
            break;
        case RET_POINTER:
            if (rax == 0)
                snprintf(retbuf, sizeof(retbuf), " = NULL");
            else
                snprintf(retbuf, sizeof(retbuf), " = %#lx", (unsigned long)rax);
            break;
        case RET_STRING: {
            char buf[65];
            if (rax == 0) {
                snprintf(retbuf, sizeof(retbuf), " = NULL");
            } else if (read_cstring(tid, rax, buf, sizeof(buf))) {
                size_t w = 0;
                w += (size_t)snprintf(retbuf, sizeof(retbuf), " = \"");
                for (const char *p = buf; *p && w + 8 < sizeof(retbuf); p++) {
                    unsigned char c = (unsigned char)*p;
                    if (c == '"' || c == '\\')
                        w += (size_t)snprintf(retbuf + w, sizeof(retbuf) - w, "\\%c", c);
                    else if (c >= 0x20 && c < 0x7f) {
                        retbuf[w++] = (char)c;
                        retbuf[w] = '\0';
                    } else
                        w += (size_t)snprintf(retbuf + w, sizeof(retbuf) - w, "\\x%02x", c);
                }
                snprintf(retbuf + w, sizeof(retbuf) - w, "\"");
            } else {
                snprintf(retbuf, sizeof(retbuf), " = %#lx", (unsigned long)rax);
            }
            break;
        }
        case RET_DOUBLE:
        case RET_FLOAT: {
            struct user_fpregs_struct fp;
            double d = 0;
            if (ptrace(PTRACE_GETFPREGS, tid, NULL, &fp) == 0) {
                unsigned long long raw;
                memcpy(&raw, fp.xmm_space, sizeof(raw));
                if (proto->ret == RET_DOUBLE)
                    memcpy(&d, &raw, sizeof(d));
                else {
                    float f;
                    memcpy(&f, &raw, sizeof(f));
                    d = (double)f;
                }
            }
            snprintf(retbuf, sizeof(retbuf), " = %g", d);
            break;
        }
        default:
            retbuf[0] = '\0';
            break;
        }
    } else {
        retbuf[0] = '\0';
    }

    printf("%s%s\n", pc->args, retbuf);
    fflush(stdout);

    pc->used = false;
    regs->rip = pc->real_retaddr;
    ptrace(PTRACE_SETREGS, tid, NULL, regs);
    ptrace(PTRACE_CONT, tid, NULL, NULL);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <pid> <symbol[,symbol...]>\n"
        "       %s -r <symbol[,symbol...]> -- <program> [args...]\n"
        "\n"
        "Attaches to a running process by pid, or runs <program> under\n"
        "tracing (tracing starts before main, so calls made during\n"
        "startup are caught).\n"
        "Press Ctrl-C to stop and print the summary.\n",
        prog, prog);
}

static pid_t run_target(char **argv)
{
    pid_t pid = fork();
    if (pid < 0)
        die("symtrace: fork: %s", strerror(errno));
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        execvp(argv[0], argv);
        fprintf(stderr, "symtrace: exec %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0)
        die("symtrace: waitpid: %s", strerror(errno));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        die("symtrace: unexpected child stop status %#x", status);
    ptrace(PTRACE_SETOPTIONS, pid, NULL,
           (void *)(long)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC));
    return pid;
}

static uint64_t entry_breakpoint_addr(pid_t pid)
{
    char exepath[64];
    snprintf(exepath, sizeof(exepath), "/proc/%d/exe", pid);
    char real[PATH_MAX];
    ssize_t n = readlink(exepath, real, sizeof(real) - 1);
    if (n < 0)
        return 0;
    real[n] = '\0';

    struct elf_file e;
    if (!elf_load_file(&e, real))
        return 0;
    if (!e.is64) {
        elf_unload(&e);
        return 0;
    }
    uint64_t entry = e.eh64->e_entry;
    elf_unload(&e);

    for (int i = 0; i < nmodules; i++)
        if (strcmp(modules[i].path, real) == 0)
            return modules[i].base + entry;
    return 0;
}

static void trace_child_from_start(pid_t pid)
{
    int status;

    load_maps(pid);
    uint64_t bp = entry_breakpoint_addr(pid);
    unsigned long orig_word = 0;
    if (bp) {
        errno = 0;
        orig_word = ptrace(PTRACE_PEEKDATA, pid, (void *)bp, NULL);
        if (errno == 0 && ptrace(PTRACE_POKEDATA, pid, (void *)bp,
                                 (void *)((orig_word & ~0xffUL) | 0xCCUL)) == 0) {
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            for (;;) {
                if (waitpid(pid, &status, 0) < 0)
                    die("symtrace: waitpid: %s", strerror(errno));
                if (WIFEXITED(status) || WIFSIGNALED(status))
                    die("symtrace: program exited before reaching entry point");
                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
                    break;
                if (WIFSTOPPED(status)) {
                    int sig = WSTOPSIG(status);
                    ptrace(PTRACE_CONT, pid, NULL,
                           sig == SIGSTOP ? NULL : (void *)(long)sig);
                }
            }
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            regs.rip = bp;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            ptrace(PTRACE_POKEDATA, pid, (void *)bp, (void *)orig_word);
        }
    }

    attach_all_threads(pid);

    nmodules = 0;
    load_maps(pid);
    setup_slots(pid, true);
}

/* After modules are loaded and the process is stopped: resolve every
 * requested symbol (GOT slots, real address, prototype from the table
 * then DWARF), then patch the GOT slots. Returns false if nothing could
 * be set up. */
static bool setup_slots(pid_t pid, bool fatal)
{
    for (int i = 0; i < nmodules; i++) {
        struct elf_file e;
        if (!elf_load_file(&e, modules[i].path))
            continue;
        find_got_slots(&e, modules[i].base);
        elf_unload(&e);
    }

    if (nslots == 0) {
        fprintf(stderr, "symtrace: no GOT slot for '%s' in %d\n",
                symbols[0], pid);
        if (fatal) {
            kill(pid, SIGKILL);
            exit(1);
        }
        return false;
    }

    for (int i = 0; i < nslots; i++) {
        struct slot *sl = &slots[i];
        sl->proto = proto_lookup(sl->symbol);

        defining_module[0] = '\0';
        sl->real_addr = resolve_real_addr(pid, sl->symbol);
        if (!sl->real_addr || !range_mapped(pid, sl->real_addr)) {
            fprintf(stderr,
                    "symtrace: cannot resolve real address of '%s' in %d\n",
                    sl->symbol, pid);
            if (fatal) {
                kill(pid, SIGKILL);
                exit(1);
            }
            continue;
        }
        if (defining_module[0] &&
            try_dwarf_proto(&sl->dw, sl->pretty, defining_module, sl->symbol))
            sl->proto = &sl->dw;

        uint64_t orig = peek(pid, sl->addr);
        if (orig == UINT64_MAX)
            continue;
        sl->orig = orig;
        uint64_t magic = MAGIC_BASE + (uint64_t)i * MAGIC_STRIDE;
        if (poke(pid, sl->addr, magic) < 0)
            fprintf(stderr, "symtrace: cannot patch GOT slot at %#lx: %s\n",
                    (unsigned long)sl->addr, strerror(errno));
    }

    /* keep only slots that were patched; compact the array */
    int w = 0;
    for (int i = 0; i < nslots; i++) {
        if (slots[i].orig) {
            if (w != i) {
                slots[w] = slots[i];
                /* re-patch magic with the new index */
                poke(pid, slots[w].addr,
                     MAGIC_BASE + (uint64_t)w * MAGIC_STRIDE);
            }
            w++;
        }
    }
    nslots = w;
    if (nslots == 0) {
        if (fatal) {
            kill(pid, SIGKILL);
            exit(1);
        }
        return false;
    }
    return true;
}

static void print_summary(void)
{
    for (int k = 0; k < nsymbols; k++) {
        uint64_t total = 0;
        for (int i = 0; i < nslots; i++)
            if (strcmp(slots[i].symbol, symbols[k]) == 0)
                total += slots[i].calls;
        printf("%s: %lu call%s intercepted\n", symbols[k],
               (unsigned long)total, total == 1 ? "" : "s");
    }
}

static int parse_symbols(const char *spec)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    char *save = NULL;
    nsymbols = 0;
    for (char *tok = strtok_r(tmp, ",", &save); tok && nsymbols < 8;
         tok = strtok_r(NULL, ",", &save)) {
        if (!tok[0])
            continue;
        bool dup = false;
        for (int i = 0; i < nsymbols; i++)
            if (strcmp(symbols[i], tok) == 0)
                dup = true;
        if (dup)
            continue;
        snprintf(symbol_buf[nsymbols], sizeof(symbol_buf[0]), "%s", tok);
        symbols[nsymbols] = symbol_buf[nsymbols];
        nsymbols++;
    }
    return nsymbols;
}

static void print_banner(void)
{
    for (int i = 0; i < nslots; i++) {
        if (slots[i].dw.name)
            printf("symtrace: prototype from debug info: %s\n",
                   slots[i].pretty);
    }
    printf("symtrace: tracing '%s' in pid %d (%d GOT slot%s) - press Ctrl-C to stop\n",
           symbols[0], target_pid, nslots, nslots > 1 ? "s" : "");
    for (int i = 1; i < nsymbols; i++)
        printf("symtrace: also tracing '%s'\n", symbols[i]);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "-r") == 0) {
        if (argc < 5 || strcmp(argv[3], "--") != 0) {
            usage(argv[0]);
            return 2;
        }
        if (parse_symbols(argv[2]) == 0) {
            fprintf(stderr, "symtrace: no symbol given\n");
            return 2;
        }

        child_launched = true;
        target_pid = run_target(&argv[4]);
        trace_child_from_start(target_pid);

        if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) < 0) {
            kill(target_pid, SIGKILL);
            die("symtrace: PTRACE_CONT: %s", strerror(errno));
        }

        print_banner();

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

        int status;
        while (1) {
            pid_t r = waitpid(-1, &status, __WALL);
            if (r < 0) {
                if (errno == EINTR) {
                    if (interrupted)
                        break;
                    continue;
                }
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                printf("symtrace: program exited (status %d)\n",
                       WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
                print_summary();
                return 0;
            }
            if (!WIFSTOPPED(status))
                continue;
            pid_t tid = r;
            int sig = WSTOPSIG(status);

            if (status >> 16 == PTRACE_EVENT_CLONE) {
                unsigned long newtid;
                if (ptrace(PTRACE_GETEVENTMSG, tid, NULL, &newtid) == 0 &&
                    nthreads < MAX_THREADS && newtid != 0)
                    threads[nthreads++] = (pid_t)newtid;
                ptrace(PTRACE_CONT, tid, NULL, NULL);
                continue;
            }

            if (sig == SIGSTOP) {
                ptrace(PTRACE_CONT, tid, NULL, NULL);
                continue;
            }

            if (sig == SIGSEGV) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, tid, NULL, &regs) == 0) {
                    if (regs.rip >= MAGIC_BASE &&
                        regs.rip < MAGIC_BASE + (uint64_t)nslots * MAGIC_STRIDE) {
                        handle_call_stop(tid, &regs,
                                         (int)((regs.rip - MAGIC_BASE) / MAGIC_STRIDE));
                        continue;
                    }
                    if (regs.rip >= MAGIC_RET_BASE &&
                        regs.rip < MAGIC_RET_BASE + (uint64_t)MAX_PENDING * MAGIC_STRIDE) {
                        handle_return_stop(tid, &regs);
                        continue;
                    }
                }
                ptrace(PTRACE_CONT, tid, NULL, (void *)(long)sig);
                continue;
            }
            ptrace(PTRACE_CONT, tid, NULL,
                   sig == SIGTRAP ? NULL : (void *)(long)sig);
        }

        for (int t = 0; t < nthreads; t++)
            kill(threads[t], SIGSTOP);
        int st2;
        int stopped = 0;
        for (int t = 0; t < nthreads; t++)
            if (waitpid(threads[t], &st2, __WALL) == threads[t] && WIFSTOPPED(st2))
                stopped++;
        if (stopped)
            restore_and_detach(target_pid);

        print_summary();
        return 0;
    }

    if (argc != 3) {
        usage(argv[0]);
        return 2;
    }

    target_pid = (pid_t)atoi(argv[1]);
    if (target_pid <= 0)
        die("symtrace: invalid pid '%s'", argv[1]);
    if (parse_symbols(argv[2]) == 0) {
        fprintf(stderr, "symtrace: no symbol given\n");
        return 2;
    }

    attach_all_threads(target_pid);

    load_maps(target_pid);
    if (!setup_slots(target_pid, false)) {
        for (int t = 0; t < nthreads; t++)
            ptrace(PTRACE_DETACH, threads[t], NULL, NULL);
        return 1;
    }

    print_banner();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (int t = 0; t < nthreads; t++) {
        if (ptrace(PTRACE_CONT, threads[t], NULL, NULL) < 0) {
            restore_and_detach(target_pid);
            die("symtrace: PTRACE_CONT on thread %d: %s",
                threads[t], strerror(errno));
        }
    }

    int status;
    while (!interrupted) {
        pid_t r = waitpid(-1, &status, __WALL);
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
        pid_t tid = r;
        int sig = WSTOPSIG(status);

        if (status >> 16 == PTRACE_EVENT_CLONE) {
            unsigned long newtid;
            if (ptrace(PTRACE_GETEVENTMSG, tid, NULL, &newtid) == 0 &&
                nthreads < MAX_THREADS && newtid != 0)
                threads[nthreads++] = (pid_t)newtid;
            ptrace(PTRACE_CONT, tid, NULL, NULL);
            continue;
        }

        if (sig == SIGSTOP) {
            ptrace(PTRACE_CONT, tid, NULL, NULL);
            continue;
        }

        if (sig == SIGSEGV) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, tid, NULL, &regs) == 0) {
                if (regs.rip >= MAGIC_BASE &&
                    regs.rip < MAGIC_BASE + (uint64_t)nslots * MAGIC_STRIDE) {
                    handle_call_stop(tid, &regs,
                                     (int)((regs.rip - MAGIC_BASE) / MAGIC_STRIDE));
                    continue;
                }
                if (regs.rip >= MAGIC_RET_BASE &&
                    regs.rip < MAGIC_RET_BASE + (uint64_t)MAX_PENDING * MAGIC_STRIDE) {
                    handle_return_stop(tid, &regs);
                    continue;
                }
            }
            ptrace(PTRACE_CONT, tid, NULL, (void *)(long)sig);
            continue;
        }
        ptrace(PTRACE_CONT, tid, NULL,
               sig == SIGTRAP ? NULL : (void *)(long)sig);
    }

    for (int t = 0; t < nthreads; t++)
        kill(threads[t], SIGSTOP);
    int st2;
    int stopped = 0;
    for (int t = 0; t < nthreads; t++)
        if (waitpid(threads[t], &st2, __WALL) == threads[t] && WIFSTOPPED(st2))
            stopped++;
    if (stopped)
        restore_and_detach(target_pid);

    print_summary();
    return 0;
}
