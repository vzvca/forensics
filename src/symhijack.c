#define _GNU_SOURCE
/*
 * symhijack - attach to a running process by PID and redirect calls to a
 * library function towards an alternative implementation contained in a
 * shared object given on the command line.
 *
 * Usage: symhijack [-w] <pid> <replacement.so> <symbol>
 *        symhijack [-w] -r <replacement.so> <symbol> -- <program> [args...]
 *
 * Mechanism (x86_64):
 *   1. PTRACE_ATTACH the target (all threads).
 *   2. In the traced process, remote-call dlopen(<replacement.so>) so the
 *      implementation becomes part of the target address space.
 *   3. Remote-call dlsym(handle, <symbol>) to get the address of the
 *      replacement entry point.
 *   4. Enumerate every GOT slot (JUMP_SLOT / GLOB_DAT relocation) in any
 *      loaded module that refers to <symbol> (same enumeration as
 *      symtrace), and overwrite each slot with the replacement address.
 *      PTRACE_POKEDATA ignores write permissions, so RELRO is not an
 *      issue.
 *   5. Detach (delivering no signal). Calls made through the PLT/GOT now
 *      land in the replacement implementation.
 *
 * With -w, stay attached and watch the target: when it exits or when the
 * tracer is interrupted, the original GOT values are restored.
 *
 * Limitations: only x86_64 targets; calls made internally within the
 * defining library that do not cross a PLT/GOT are not redirected.
 */

#include "elfparse.h"
#include "common/pt.h"
#include "common/remote.h"
#include "common/target.h"

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
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_SLOTS 4096

static struct target tgt;
static struct target_slot slots[MAX_SLOTS];
static int nslots;
static pid_t target_pid;
static volatile sig_atomic_t interrupted;
static bool watch_mode;
static bool child_launched;

static struct target_slot live_slots[MAX_SLOTS];
static int nlive;

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

static void attach_all_threads(pid_t pid)
{
    char taskdir[64];
    snprintf(taskdir, sizeof(taskdir), "/proc/%d/task", pid);
    DIR *d = opendir(taskdir);
    if (!d)
        die("symhijack: cannot open %s: %s", taskdir, strerror(errno));
    struct dirent *ent;
    tgt.nthreads = 0;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;
        pid_t tid = (pid_t)atoi(ent->d_name);
        if (tgt.nthreads >= TARGET_MAX_THREADS)
            break;
        if (child_launched) {
            tgt.threads[tgt.nthreads++] = tid;
            continue;
        }
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
            fprintf(stderr, "symhijack: cannot attach to thread %d: %s\n",
                    tid, strerror(errno));
            continue;
        }
        tgt.threads[tgt.nthreads++] = tid;
    }
    closedir(d);
    if (tgt.nthreads == 0)
        die("symhijack: could not attach to any thread of %d", pid);
    if (child_launched)
        return;
    for (int t = 0; t < tgt.nthreads; t++) {
        int status;
        pid_t r;
        do {
            r = waitpid(tgt.threads[t], &status, __WALL);
        } while (r < 0 && errno == EINTR);
        if (r != tgt.threads[t])
            continue;
        ptrace(PTRACE_SETOPTIONS, tgt.threads[t], NULL,
               (void *)(long)PTRACE_O_TRACECLONE);
    }
}

static void restore_and_detach(void)
{
    for (int i = 0; i < nlive; i++)
        pt_poke(target_pid, live_slots[i].addr, live_slots[i].orig);
    for (int t = 0; t < tgt.nthreads; t++)
        ptrace(PTRACE_DETACH, tgt.threads[t], NULL, NULL);
}

static void detach_all(void)
{
    for (int t = 0; t < tgt.nthreads; t++)
        ptrace(PTRACE_DETACH, tgt.threads[t], NULL, NULL);
}

static pid_t run_target(char **argv)
{
    pid_t pid = fork();
    if (pid < 0)
        die("symhijack: fork: %s", strerror(errno));
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        execvp(argv[0], argv);
        fprintf(stderr, "symhijack: exec %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0)
        die("symhijack: waitpid: %s", strerror(errno));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        die("symhijack: unexpected child stop status %#x", status);
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

    int m = target_find_module(&tgt, real);
    if (m < 0)
        return 0;
    return tgt.modules[m].base + entry;
}

/* Stop the freshly exec'd child at its entry point (after ld.so has
 * mapped everything) so that dlopen can be called immediately. */
static void stop_child_at_entry(pid_t pid)
{
    target_load_maps(&tgt);
    uint64_t bp = entry_breakpoint_addr(pid);
    if (!bp)
        die("symhijack: cannot locate target entry point");

    errno = 0;
    unsigned long orig_word = ptrace(PTRACE_PEEKDATA, pid, (void *)bp, NULL);
    if (errno)
        die("symhijack: cannot read entry point: %s", strerror(errno));
    if (ptrace(PTRACE_POKEDATA, pid, (void *)bp,
               (void *)((orig_word & ~0xffUL) | 0xCCUL)) < 0)
        die("symhijack: cannot set entry breakpoint: %s", strerror(errno));

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    int status;
    for (;;) {
        if (waitpid(pid, &status, 0) < 0)
            die("symhijack: waitpid: %s", strerror(errno));
        if (WIFEXITED(status) || WIFSIGNALED(status))
            die("symhijack: program exited before reaching entry point");
        if (!WIFSTOPPED(status))
            continue;
        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP)
            break;
        ptrace(PTRACE_CONT, pid, NULL,
               sig == SIGSTOP ? NULL : (void *)(long)sig);
    }
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = bp;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_POKEDATA, pid, (void *)bp, (void *)orig_word);

    tgt.nmodules = 0;
    target_load_maps(&tgt);
    attach_all_threads(pid);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-w] <pid> <replacement.so> <symbol>\n"
        "       %s [-w] -r <replacement.so> <symbol> -- <program> [args...]\n"
        "\n"
        "Redirects calls to <symbol> in the target process towards the\n"
        "implementation of <symbol> found in <replacement.so>. The .so is\n"
        "dlopen'ed inside the target and the GOT slots that reference\n"
        "<symbol> are rewritten to point at the replacement.\n"
        "\n"
        "  -w  watch mode: stay attached and restore the original GOT\n"
        "      values when the target exits or on Ctrl-C\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    const char *so_path = NULL;
    const char *symbol = NULL;
    int argi = 1;

    if (argi < argc && strcmp(argv[argi], "-w") == 0) {
        watch_mode = true;
        argi++;
    }

    bool run_mode = false;
    if (argi < argc && strcmp(argv[argi], "-r") == 0) {
        run_mode = true;
        argi++;
    }

    if (run_mode) {
        if (argc - argi < 3 || strcmp(argv[argi + 2], "--") != 0) {
            usage(argv[0]);
            return 2;
        }
        so_path = argv[argi];
        symbol = argv[argi + 1];
        child_launched = true;
        target_pid = run_target(&argv[argi + 3]);
        target_init(&tgt, target_pid);
        stop_child_at_entry(target_pid);
    } else {
        if (argc - argi != 3) {
            usage(argv[0]);
            return 2;
        }
        target_pid = (pid_t)atoi(argv[argi]);
        if (target_pid <= 0)
            die("symhijack: invalid pid '%s'", argv[argi]);
        so_path = argv[argi + 1];
        symbol = argv[argi + 2];
        target_init(&tgt, target_pid);
        attach_all_threads(target_pid);
    }

    /* Work on the first attached thread (the process must be stopped). */
    pid_t tid = tgt.threads[0];

    target_load_maps(&tgt);

    /* Resolve the .so to an absolute path: dlopen runs in the target. */
    char abs[PATH_MAX];
    if (!realpath(so_path, abs))
        die("symhijack: cannot resolve %s: %s", so_path, strerror(errno));

    uint64_t handle = remote_dlopen(tid, abs, 2 /* RTLD_NOW */);
    if (!handle)
        die("symhijack: remote dlopen(%s) failed", abs);
    printf("symhijack: %s loaded in pid %d (handle %#lx)\n",
           abs, target_pid, (unsigned long)handle);

    uint64_t newaddr = remote_dlsym(tid, handle, symbol);
    if (!newaddr || !target_range_mapped(&tgt, newaddr))
        die("symhijack: remote dlsym(%s) failed in %s", symbol, abs);
    printf("symhijack: replacement %s at %#lx\n", symbol, (unsigned long)newaddr);

    nslots = target_find_got_slots(&tgt, symbol, slots, MAX_SLOTS);
    if (nslots == 0)
        die("symhijack: no GOT slot for '%s' in pid %d", symbol, target_pid);

    nlive = 0;
    for (int i = 0; i < nslots; i++) {
        if (!slots[i].orig)
            continue;
        if (pt_poke(target_pid, slots[i].addr, newaddr) < 0) {
            fprintf(stderr, "symhijack: cannot patch GOT slot at %#lx: %s\n",
                    (unsigned long)slots[i].addr, strerror(errno));
            continue;
        }
        live_slots[nlive] = slots[i];
        nlive++;
    }
    if (nlive == 0)
        die("symhijack: could not patch any GOT slot for '%s'", symbol);

    printf("symhijack: %d GOT slot%s for '%s' redirected to %#lx\n",
           nlive, nlive > 1 ? "s" : "", symbol, (unsigned long)newaddr);

    if (!watch_mode) {
        detach_all();
        printf("symhijack: detached, calls now land in the replacement\n");
        return 0;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (int t = 0; t < tgt.nthreads; t++)
        ptrace(PTRACE_CONT, tgt.threads[t], NULL, NULL);

    printf("symhijack: watching pid %d - press Ctrl-C to restore and detach\n",
           target_pid);

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
        pid_t stid = r;
        int sig = WSTOPSIG(status);

        if (status >> 16 == PTRACE_EVENT_CLONE) {
            unsigned long newtid;
            if (ptrace(PTRACE_GETEVENTMSG, stid, NULL, &newtid) == 0 &&
                tgt.nthreads < TARGET_MAX_THREADS && newtid != 0)
                tgt.threads[tgt.nthreads++] = (pid_t)newtid;
            ptrace(PTRACE_CONT, stid, NULL, NULL);
            continue;
        }
        if (sig == SIGSTOP) {
            ptrace(PTRACE_CONT, stid, NULL, NULL);
            continue;
        }
        ptrace(PTRACE_CONT, stid, NULL,
               sig == SIGTRAP ? NULL : (void *)(long)sig);
    }

    for (int t = 0; t < tgt.nthreads; t++)
        kill(tgt.threads[t], SIGSTOP);
    int st2;
    int stopped = 0;
    for (int t = 0; t < tgt.nthreads; t++)
        if (waitpid(tgt.threads[t], &st2, __WALL) == tgt.threads[t] &&
            WIFSTOPPED(st2))
            stopped++;
    if (stopped)
        restore_and_detach();

    printf("symhijack: original GOT values restored\n");
    return 0;
}
