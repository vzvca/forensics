#ifndef FORENSICS_ELFPARSE_H
#define FORENSICS_ELFPARSE_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ELF_MAX_NEEDED 128

struct elf_file {
    char path[PATH_MAX];
    bool is64;
    const unsigned char *base;
    size_t size;
    Elf64_Ehdr *eh64;
    Elf32_Ehdr *eh32;
    const char *strtab;
    size_t strsz;
    const char *symtab;
    size_t syment;
    size_t symcount;
    const char *needed[ELF_MAX_NEEDED];
    int needed_count;
    const char *rpath;
    const char *runpath;
    uint64_t jmprel;
    uint64_t pltrelsz;
    uint64_t pltreltype;
    uint64_t rela;
    uint64_t relasz;
    uint64_t rel;
    uint64_t relsz;
};

bool elf_load_file(struct elf_file *e, const char *path);
void elf_unload(struct elf_file *e);

size_t elf_sym_count(const struct elf_file *e);
const char *elf_sym_name(const struct elf_file *e, size_t idx);
bool elf_sym_defined(const struct elf_file *e, size_t idx);
uint64_t elf_sym_value(const struct elf_file *e, size_t idx);
uint16_t elf_sym_shndx(const struct elf_file *e, size_t idx);

const char *elf_sym_name_by_rva(const struct elf_file *e, uint64_t vaddr,
                                uint64_t *symval);

#endif
