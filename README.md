# forensics

> [!NOTE]
> Le code de ce dépôt a été écrit par l'agent IA de Mistral (Vibe Code,
> propulsé par le modèle GLM de Z.ai) dans le cadre du programme de bêta
> de codage autonome de Mistral AI.

Tools for debugging running processes on Linux (x86_64).

## Tools

### symfind

Find which shared library defines a symbol among the ELF dependencies of a
binary.

    symfind <binary> <symbol>
    symfind -g <binary> '<glob>'
    symfind -r <binary> '<regex>'

### symtrace

Attach to a running process (by PID) or launch a program, and trace every
call to a function identified by its symbol name — like strace does for
system calls, but for library functions. Arguments and return values are
decoded using hard-coded prototypes or DWARF debug information when
available.

    symtrace <pid> <symbol[,symbol...]>
    symtrace -r <symbol[,symbol...]> -- <program> [args...]

Mechanism: the GOT slots (JUMP_SLOT / GLOB_DAT relocations) that reference
the symbol are overwritten with magic unmapped addresses; each SIGSEGV on a
magic address is one call, and RIP is redirected to the real function.

### symhijack

Attach to a running process (by PID) or launch a program, and permanently
redirect calls to a library function towards an alternative implementation
shipped in a shared object given on the command line.

    symhijack [-w] <pid> <replacement.so> <symbol>
    symhijack [-w] -r <replacement.so> <symbol> -- <program> [args...]

Mechanism (shares the GOT enumeration with symtrace):

 1. PTRACE_ATTACH the target (all threads).
 2. In the traced process, remote-call `dlopen(<replacement.so>)` so the
    alternative implementation becomes part of the target address space.
    The remote call works by setting up registers/stack of a stopped
    thread and continuing until it faults on a magic return address.
 3. Remote-call `dlsym(handle, <symbol>)` to locate the replacement entry
    point.
 4. Overwrite every GOT slot referencing `<symbol>` (across all loaded
    modules) with the replacement address. PTRACE_POKEDATA ignores page
    permissions, so RELRO is not an obstacle.
 5. Detach. Calls made through the PLT/GOT now land in the replacement.

With `-w`, symhijack stays attached and restores the original GOT values
when the target exits or on Ctrl-C.

Limitations: x86_64 only; calls that stay internal to the defining library
(without crossing a PLT/GOT) are not redirected; the replacement library is
loaded with RTLD_NOW.

### dwproto

Dump DWARF function prototypes in the `prototypes.h` format used by
symtrace.

    dwproto <binary-or-library> [function]

## Build and tests

    make
    make test

The shared tooling lives in `src/common/`: ptrace helpers (`pt.c`), target
module/GOT enumeration reused by symtrace and symhijack (`target.c`), and
remote function-call machinery used to run dlopen/dlsym inside the traced
process (`remote.c`).
