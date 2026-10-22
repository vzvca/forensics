# forensics

> [!NOTE]
> **About the authorship**
>
> This program and its documentation were written from A to Z by
> **mistral-vibe** (Mistral AI's coding agent, powered by the GLM model),
> under human supervision: the project owner defined the goals and
> reviewed, tested and merged each step.

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

Limitation: x86_64 only; calls that stay internal to the defining library
(without crossing a PLT/GOT) are not redirected; the replacement library is
loaded with RTLD_NOW.

Limitation: dlopen needs to be defined in libc (which start with debian 12)


### dwproto

Dump DWARF function prototypes in the `prototypes.h` format used by
symtrace.

    dwproto <binary-or-library> [function]

Can be used to modify `prototypes.h` to add more prototypes.


## Build and tests

    make
    make test

The shared tooling lives in `src/common/`: ptrace helpers (`pt.c`), target
module/GOT enumeration reused by symtrace and symhijack (`target.c`), and
remote function-call machinery used to run dlopen/dlsym inside the traced
process (`remote.c`).

## Example

There is an example:

    cd example
    ./runme.sh

Expected output (debian trixie):

    == building
    cc -shared -g3 -o bad.so bad-factorial.c
    cc -shared -g3 -o good.so good-factorial.c
    cc -o main -g3 main.c bad.so
    == ldd output
	    linux-vdso.so.1 (0x00007ffcf55a8000)
	    bad.so => /home/vzvca/forensics/example/bad.so (0x00007f1d28dba000)
	    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1d28bc4000)
	    /lib64/ld-linux-x86-64.so.2 (0x00007f1d28dc6000)
    == symfind facto
    /home/localadmin/vincent/forensics/example/bad.so: facto
    == symtrace output
    symtrace: prototype from debug info: facto(int)
    symtrace: prototype from debug info: facto(int)
    symtrace: tracing 'facto' in pid 596 (2 GOT slots) - press Ctrl-C to stop
    facto(1) = 1
    facto(2) = 2
    facto(3) = 6
    facto(4) = 24
    facto(5) = 120
    facto(6) = 720
    GOOD => 6! = 720
    facto(0) = 0
    BAD  => 0! = 0
    symtrace: program exited (status 0)
    facto: 7 calls intercepted
    == symhijack output
    symhijack: /home/vzvca/forensics/example/good.so loaded in pid 598 (handle 0x55ebec5452e0)
    symhijack: replacement facto at 0x7f7d6b41e109
    symhijack: 2 GOT slots for 'facto' redirected to 0x7f7d6b41e109
    symhijack: detached, calls now land in the replacement
    GOOD => 6! = 720
    BAD  => 0! = 1
