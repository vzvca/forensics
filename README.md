# forensics

Tools for debugging.

## symfind

`symfind` tells you which shared library, among all the dependencies
(transitive included) of an ELF executable or library, **defines** a given
symbol. It reads ELF files directly from disk (mmap + manual parsing of the
program headers, `.dynamic`, `.dynsym` and `.dynstr`), with no external
dependency beyond libc.

### Usage

```
symfind [-g|-r] <elf-file> <pattern>
```

By default `<pattern>` is matched literally. With `-g` it is treated as a
shell glob (fnmatch), with `-r` as an extended regular expression
(POSIX ERE). Every defined symbol matching the pattern is printed as
`<library>: <symbol>`, across the file and all its transitive dependencies.

```
$ symfind /bin/ls printf
/lib/x86_64-linux-gnu/libc.so.6: printf

$ symfind -g /bin/ls 'printf_*'
/lib/x86_64-linux-gnu/libc.so.6: printf_size
/lib/x86_64-linux-gnu/libc.so.6: printf_size_info

$ symfind -r /bin/grep '^pc?re2_compile'
/lib/x86_64-linux-gnu/libpcre2-8.so.0: pcre2_compile_8
```

- exit code 0: at least one symbol matched
- exit code 1: no symbol matched in the file or any of its dependencies
- exit code 2: usage error, invalid regex, or unreadable file

### How it works

1. Opens the ELF file, validates the magic and the class (32/64-bit).
2. Walks `PT_LOAD` program headers to translate virtual addresses
   (`DT_STRTAB`, `DT_SYMTAB`) into file offsets.
3. Parses `PT_DYNAMIC` in two passes (first collect `DT_STRTAB`/`DT_STRSZ`,
   then read `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`).
4. Scans `.dynsym` for a **defined** symbol (non-null `st_value`,
   `st_shndx != SHN_UNDEF`) matching the pattern.
5. Resolves each `DT_NEEDED` entry with the same search order as the dynamic
   loader: `DT_RUNPATH`, `LD_LIBRARY_PATH`, `DT_RPATH`, then the default
   system directories. `$ORIGIN`, `$LIB` and `$PLATFORM` tokens are expanded.
6. Recurses into every dependency (already-seen libraries are skipped,
   depth-capped) and lists all matches.

### Limitations

- Only `.dynsym` (dynamic symbols) is inspected, which is what the loader
  uses; this works even on stripped libraries.
- Versioned symbols match by name only (the `@@VERSION` suffix is ignored),
  like `dlsym` without a version constraint.
- `ld.so.cache` is not parsed; the default search path is a static list of
  common directories.

## symtrace

`symtrace` attaches to a **running process** identified by its PID and
counts every call to a function identified by its symbol name. The library
that actually provides the function is discovered by reusing the same
ELF-parsing core as `symfind`. With `-r`, the program is forked with
`PTRACE_TRACEME` and a breakpoint is placed on the ELF entry point, so
tracing is active before `main` runs and calls made during startup
(static constructors, library init) are caught too. The trace ends
automatically when the program exits.

### Usage

```
symtrace <pid> <symbol>                    # attach to a running process
symtrace -r <symbol> -- <program> [args]   # start a program under tracing
```

Press Ctrl-C to stop tracing; the summary is printed:

```
$ symtrace 12345 fopen
symtrace: tracing 'fopen' in pid 12345 (1 GOT slot) - press Ctrl-C to stop
fopen("/etc/hostname", "r") = 0x56409c6ad2a0
fopen("/var/log/syslog", "a") = 0x56409c6ad6f0
^C
fopen: 2 calls intercepted
```

### Argument display

At each SIGSEGV stop the registers hold exactly the state at function
entry (the `call` has pushed the return address; only RIP is rewritten),
so arguments are decoded following the System V AMD64 ABI: INTEGER-class
arguments come from `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` then the stack
(`rsp+8`, `rsp+16`, ...), SSE-class arguments from `xmm0`..`xmm7`.
Strings are read from the target with ptrace and printed escaped and
truncated to 64 bytes.

Prototypes are currently hard-coded in `src/prototypes.h` (malloc, the
stdio family, string functions, sockets, pthreads, ...). For functions
with a known prototype the arguments are printed decoded; otherwise the
six INTEGER registers are dumped raw:

```
malloc(1024)
read(3, 0x7f00a1b2c3d0, 4096)
somefunc(rdi=0x1 rsi=0x7ffd0000 rdx=0x0 rcx=0x0 r8=0x0 r9=0x7f00...)
```

### Prototypes from debug info (DWARF)

If the module that defines the traced symbol carries DWARF debug
information - either inline (compiled with `-g`) or in a separate file
referenced by the `.gnu_debuglink` section (`objcopy --only-keep-debug`
+ `strip -g` workflow, also `/usr/lib/debug/...`) - symtrace parses
`.debug_info`/`.debug_abbrev`/`.debug_str`/`.debug_line_str` (DWARF 4
and 5) itself, extracts the `DW_TAG_subprogram` entry, follows the
`DW_AT_type` chains of its formal parameters and classifies them
(int/unsigned/char/char*/ptr/double/float). The hard-coded table is
only a fallback:

```
$ symtrace -r greet -- ./dwmain
symtrace: prototype from debug info: greet(char*, int)
symtrace: tracing 'greet' in pid 3772 (2 GOT slots) - press Ctrl-C to stop
greet("world", 1) = 12
...
```

The resolved prototype is printed in the banner so it is always visible
which decoding is in effect. The DWARF parser is self-contained C
(`src/dwarg.c`, no libdw/libelf dependency), handles 32/64-bit DWARF
offsets, recursive typedef chains, pointer-to-char detection (printed as
a string), and stops at `DW_TAG_unspecified_parameters` for variadic
functions.

### Return value capture

The return address pushed by the caller's `call` sits at `[rsp]` at the
entry stop. symtrace replaces it with a second magic unmapped address,
lets the real function run to completion, and catches the resulting
SIGSEGV when it executes `ret`. At that stop `rax` (or `xmm0`) holds the
return value; RIP is restored to the original return address so the
target continues exactly as if nothing happened. Each in-flight call has
its own magic return address on its own stack, so nested and concurrent
calls are handled naturally; functions that never return (exit, longjmp)
simply leave a harmless magic address on an abandoned stack.

The return type comes from the prototype table: `malloc(64) = 0x56409c6ad2a0`,
`strcmp("a","b") = -1`, `fopen("/x","r") = NULL` for a failure.

### How it works (GOT hijacking, no code injection)

1. `PTRACE_ATTACH` the target, then enumerate its loaded modules from
   `/proc/<pid>/maps`.
2. Parse every module on disk with the shared ELF core and collect all
   dynamic relocations (`R_X86_64_JUMP_SLOT`, `R_X86_64_GLOB_DAT`) that
   reference `<symbol>` — each relocation gives the live address of one
   GOT slot in the target.
3. Resolve the real address of the function (defining module's symbol
   table, or an already-resolved GOT slot).
4. Overwrite each GOT slot with a distinct **magic unmapped address** using
   `PTRACE_POKEDATA`. Since ptrace writes bypass page permissions, Full
   RELRO binaries are handled without `mprotect` tricks.
5. Resume the process. Every call to the function now jumps to the magic
   address and raises `SIGSEGV`; the tracer catches the stop, counts it,
   rewrites RIP to the real function address and resumes. The call proceeds
   normally — the target never crashes and its behaviour is unchanged.
6. On exit, the original GOT values are restored, then the target is
   detached.

### SIGSEGV handlers in the target

The magic addresses are unmapped on purpose: each call faults. A ptrace
tracer sees every signal **before** it is delivered to the traced process,
so symtrace intercepts the SIGSEGV, rewrites RIP to the real function and
resumes; a SIGSEGV handler installed by the target (sigaction) is never
invoked for these faults. Genuine segmentation faults are forwarded
untouched with the signal delivered, so the target behaves exactly as if
symtrace was not there.

### Limitations

- x86_64 targets only, SysV C ABI only for now (variadic functions,
  struct returns and by-value structs need a prototype description).
- Only calls that cross a PLT/GOT are seen: calls made *internally* within
  the defining library (e.g. libc calling its own `fopen` internally) do not
  go through a GOT slot and are not counted.
- Every counted call costs a ptrace stop/start round-trip, so traced
  programs run slower (fine for debugging, not for hot loops).
- Each module in the process has its own GOT; slots are patched in every
  mapped module that imports the symbol.

## Build / Test

```
make        # builds symfind and symtrace
make test   # builds fixtures and runs the test suite
make install
```

The test suite covers: symbol defined in the analyzed binary itself, symbol
defined in a dependency, glob and regex patterns, missing symbol, invalid
regex, and an end-to-end symtrace run against a live victim process.

## License

MIT — see [LICENSE](LICENSE).
