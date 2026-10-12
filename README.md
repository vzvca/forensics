# forensics

Tools for debugging.

## symfind

`symfind` tells you which shared library, among all the dependencies
(transitive included) of an ELF executable or library, **defines** a given
symbol. It reads ELF files directly from disk (mmap + manual parsing of the
program headers, `.dynamic`, `.dynsym` and `.dynstr`), with no external
dependency beyond libc.

```
$ symfind /bin/ls printf
/lib/x86_64-linux-gnu/libc.so.6

$ symfind /bin/grep pcre2_compile_8
/lib/x86_64-linux-gnu/libpcre2-8.so.0
```

### Build

```
make
```

### Test

```
make test
```

The suite builds fixtures on the fly (a shared library and an executable
that both export symbols) and checks the three cases: symbol defined in the
analyzed binary itself, symbol defined in a dependency, and symbol absent
from the whole closure.

### Usage

```
symfind <elf-file> <symbol>
```

- exit code 0: the symbol was found, its defining library is printed on stdout
- exit code 1: the symbol is not defined by the file or any of its
  dependencies
- exit code 2: usage error

### How it works

1. Opens the ELF file, validates the magic and the class (32/64-bit).
2. Walks `PT_LOAD` program headers to translate virtual addresses
   (`DT_STRTAB`, `DT_SYMTAB`) into file offsets.
3. Parses `PT_DYNAMIC` in two passes (first collect `DT_STRTAB`/`DT_STRSZ`,
   then read `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`).
4. Scans `.dynsym` for a **defined** symbol (non-null `st_value`,
   `st_shndx != SHN_UNDEF`) matching the requested name.
5. Resolves each `DT_NEEDED` entry with the same search order as the dynamic
   loader: `DT_RUNPATH`, `LD_LIBRARY_PATH`, `DT_RPATH`, then the default
   system directories (`/lib`, `/usr/lib`, multi-arch directories, ...).
   `$ORIGIN`, `$LIB` and `$PLATFORM` tokens in RPATH/RUNPATH are expanded.
6. Recurses into every dependency (already-seen libraries are skipped,
   depth-capped) until a definition is found.

### Limitations

- Only `.dynsym` (dynamic symbols) is inspected, which is what the loader
  uses; this works even on stripped libraries.
- Versioned symbols match by name only (the `@@VERSION` suffix is ignored),
  like `dlsym` without a version constraint.
- `ld.so.cache` is not parsed; the default search path is a static list of
  common directories.
