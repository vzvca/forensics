#include "remote.h"

#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define REMOTE_RET_MAGIC 0x6f3ab9c5d1e2ULL

/*
 * Call func(args...) in the traced thread. The remote return address is a
 * magic value that is (normally) unmapped: when the function returns, the
 * thread SIGSEGVs with rip == magic, which we detect as "call completed".
 * Registers and the top-of-stack word are restored before returning.
 * Returns 0 on success with *retval set, -1 on failure.
 */
int remote_call(pid_t tid, uint64_t func, const uint64_t args[6],
                uint64_t *retval)
{
    struct user_regs_struct regs, saved;
    if (pt_getregs(tid, &regs) < 0)
        return -1;
    saved = regs;

    /* Emulate a CALL: the fake return address sits at sp, so at function
     * entry rsp % 16 must be 8 (as after a real call from a 16-aligned
     * stack), otherwise SSE code in the callee faults on movaps. */
    uint64_t sp = ((regs.rsp - 256) & ~(uint64_t)15) - 8;
    if (pt_poke(tid, sp, REMOTE_RET_MAGIC) < 0)
        return -1;

    regs.rip = func;
    regs.rsp = sp;
    /* If the thread was blocked in a syscall, prevent the kernel from
     * rewinding RIP to restart it (-ERESTARTSYS/-ERESTARTNOINTR...): with
     * rax set to an error the syscall exit path does not rewind. */
    regs.rax = (uint64_t)-39; /* -ENOSYS */
    regs.eflags &= ~0x100; /* clear TF, keep other flags */
    regs.orig_rax = (uint64_t)-1;
    if (args) {
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.rcx = args[3];
        regs.r8  = args[4];
        regs.r9  = args[5];
    }
    if (pt_setregs(tid, &regs) < 0)
        return -1;

    if (pt_cont(tid, 0) < 0)
        return -1;

    int status;
    for (;;) {
        if (pt_wait(tid, &status) < 0)
            return -1;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            errno = ESRCH;
            return -1;
        }
        if (!WIFSTOPPED(status))
            continue;
        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP) {
            /* breakpoint / trap inside the callee: not supported, abort */
            errno = EFAULT;
            return -1;
        }
        if (sig == SIGSEGV) {
            if (pt_getregs(tid, &regs) < 0)
                return -1;
            /* The fake return address is unmapped: the thread faults either
             * right after returning (rip == MAGIC) or on the ret/jmp that
             * targets it, with MAGIC still on top of the stack. */
            bool done = regs.rip == REMOTE_RET_MAGIC;
            if (!done) {
                uint64_t top;
                if (pt_peek(tid, regs.rsp, &top) == 0 && top == REMOTE_RET_MAGIC)
                    done = true;
            }
            if (!done) {
                errno = EFAULT;
                return -1;
            }
            uint64_t ret = regs.rax;
            if (pt_setregs(tid, &saved) < 0)
                return -1;
            if (retval)
                *retval = ret;
            return 0;
        }
        /* deliver other signals and keep waiting for the call to finish */
        if (pt_cont(tid, sig) < 0)
            return -1;
    }
}

/*
 * Resolve a libc symbol by reading the target's own GOT: the tracer scans
 * the target modules for a PLT relocation against <symbol> and reads the
 * resolved slot value. Works for dlopen/dlsym/mmap because the tracer
 * itself links against them, so they are guaranteed to exist.
 */
static uint64_t remote_libc_sym(pid_t pid, const char *symbol)
{
    (void)pid;

    /* locate libc in the target via /proc/<pid>/maps, then its .dynsym */
    char mapsfile[64];
    snprintf(mapsfile, sizeof(mapsfile), "/proc/%d/maps", pid);
    FILE *f = fopen(mapsfile, "r");
    if (!f)
        return 0;
    char line[512];
    char libcpath[512] = "";
    while (fgets(line, sizeof(line), f)) {
        char path[512];
        path[0] = '\0';
        if (sscanf(line, "%*x-%*x %*s %*x %*s %*s %511s", path) == 1 &&
            strstr(path, "/libc.so")) {
            snprintf(libcpath, sizeof(libcpath), "%s", path);
            break;
        }
    }
    fclose(f);
    if (!libcpath[0])
        return 0;

    uint64_t base = 0;
    f = fopen(mapsfile, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            char path[512];
            unsigned long start, off;
            path[0] = '\0';
            if (sscanf(line, "%lx-%*x %*s %lx %*s %*s %511s", &start, &off, path) == 3 &&
                off == 0 && path[0] && strcmp(path, libcpath) == 0) {
                base = start;
                break;
            }
        }
        fclose(f);
    }
    if (!base)
        return 0;

    char dbgsym[256];
    snprintf(dbgsym, sizeof(dbgsym), "%s", symbol);
    char nmcmd[1024];
    snprintf(nmcmd, sizeof(nmcmd),
             "nm -D %s 2>/dev/null | grep -E ' (T|W|i) (%s|__%s)(@|$)' | head -1",
             libcpath, dbgsym, dbgsym);
    FILE *nm = popen(nmcmd, "r");
    if (!nm)
        return 0;
    char nmline[512];
    uint64_t val = 0;
    if (fgets(nmline, sizeof(nmline), nm))
        sscanf(nmline, "%lx", &val);
    pclose(nm);
    if (!val)
        return 0;
    return base + val;
}

uint64_t remote_mmap(pid_t tid, uint64_t addr, size_t len, int prot, int flags)
{
    uint64_t func = remote_libc_sym(tid, "mmap");
    if (!func)
        return 0;
    uint64_t args[6] = { addr, (uint64_t)len, (uint64_t)prot,
                         (uint64_t)flags, (uint64_t)-1, 0 };
    uint64_t ret = 0;
    if (remote_call(tid, func, args, &ret) < 0)
        return 0;
    if (ret > UINT64_MAX - 4096)
        return 0;
    return ret;
}

uint64_t remote_dlopen(pid_t tid, const char *path, int mode)
{
    uint64_t func = remote_libc_sym(tid, "dlopen");
    if (!func)
        return 0;
    uint64_t straddr = remote_mmap(tid, 0, 4096, 3 /*RW*/, 0x22 /*MAP_PRIVATE|MAP_ANON*/);
    if (!straddr)
        return 0;
    if (pt_write_mem(tid, straddr, path, strlen(path) + 1) < 0)
        return 0;
    uint64_t args[6] = { straddr, (uint64_t)(unsigned)mode, 0, 0, 0, 0 };
    uint64_t ret = 0;
    if (remote_call(tid, func, args, &ret) < 0)
        return 0;
    return ret;
}

uint64_t remote_dlsym(pid_t tid, uint64_t handle, const char *symbol)
{
    uint64_t func = remote_libc_sym(tid, "dlsym");
    if (!func)
        return 0;
    uint64_t straddr = remote_mmap(tid, 0, 4096, 3 /*RW*/, 0x22);
    if (!straddr)
        return 0;
    if (pt_write_mem(tid, straddr, symbol, strlen(symbol) + 1) < 0)
        return 0;
    uint64_t args[6] = { handle, straddr, 0, 0, 0, 0 };
    uint64_t ret = 0;
    if (remote_call(tid, func, args, &ret) < 0)
        return 0;
    return ret;
}
