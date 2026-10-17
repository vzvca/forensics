#include "elfparse.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void *mmap_file(const char *path, size_t *size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf32_Ehdr)) {
        close(fd);
        return NULL;
    }
    void *p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return NULL;
    *size = st.st_size;
    return p;
}

static size_t vaddr_to_offset(const struct elf_file *e, uint64_t vaddr)
{
    if (e->is64) {
        for (int i = 0; i < e->eh64->e_phnum; i++) {
            Elf64_Phdr *ph =
                (Elf64_Phdr *)(e->base + e->eh64->e_phoff + i * e->eh64->e_phentsize);
            if (ph->p_type == PT_LOAD && vaddr >= ph->p_vaddr &&
                vaddr < ph->p_vaddr + ph->p_filesz)
                return (size_t)(vaddr - ph->p_vaddr + ph->p_offset);
        }
    } else {
        for (int i = 0; i < e->eh32->e_phnum; i++) {
            Elf32_Phdr *ph =
                (Elf32_Phdr *)(e->base + e->eh32->e_phoff + i * e->eh32->e_phentsize);
            if (ph->p_type == PT_LOAD && vaddr >= ph->p_vaddr &&
                vaddr < ph->p_vaddr + ph->p_filesz)
                return (size_t)(vaddr - ph->p_vaddr + ph->p_offset);
        }
    }
    return 0;
}

static const char *get_ptr(const struct elf_file *e, uint64_t vaddr, uint64_t size)
{
    size_t off = vaddr_to_offset(e, vaddr);
    if (!off || off + size > e->size)
        return NULL;
    return (const char *)(e->base + off);
}

static void parse_dynamic(struct elf_file *e)
{
    const unsigned char *dyn = NULL;

    if (e->is64) {
        for (int i = 0; i < e->eh64->e_phnum; i++) {
            Elf64_Phdr *ph =
                (Elf64_Phdr *)(e->base + e->eh64->e_phoff + i * e->eh64->e_phentsize);
            if (ph->p_type == PT_DYNAMIC) {
                size_t off = (size_t)ph->p_offset;
                if (off + ph->p_filesz <= e->size)
                    dyn = e->base + off;
                break;
            }
        }
    } else {
        for (int i = 0; i < e->eh32->e_phnum; i++) {
            Elf32_Phdr *ph =
                (Elf32_Phdr *)(e->base + e->eh32->e_phoff + i * e->eh32->e_phentsize);
            if (ph->p_type == PT_DYNAMIC) {
                size_t off = (size_t)ph->p_offset;
                if (off + ph->p_filesz <= e->size)
                    dyn = e->base + off;
                break;
            }
        }
    }

    if (!dyn)
        return;

    uint64_t strtab_vaddr = 0;
    uint64_t rpath_off = 0, runpath_off = 0;

    for (int pass = 0; pass < 2; pass++) {
        if (e->is64) {
            for (size_t i = 0;; i++) {
                Elf64_Dyn *d = (Elf64_Dyn *)(dyn + i * sizeof(Elf64_Dyn));
                if ((const unsigned char *)d + sizeof(*d) > e->base + e->size)
                    break;
                if (d->d_tag == DT_NULL)
                    break;
                switch (d->d_tag) {
                case DT_STRTAB:   strtab_vaddr = d->d_un.d_ptr; break;
                case DT_STRSZ:    e->strsz = d->d_un.d_val; break;
                case DT_SYMTAB:   e->symtab = get_ptr(e, d->d_un.d_ptr, sizeof(Elf64_Sym)); break;
                case DT_SYMENT:   e->syment = d->d_un.d_val; break;
                case DT_RPATH:    rpath_off = d->d_un.d_val; break;
                case DT_RUNPATH:  runpath_off = d->d_un.d_val; break;
                case DT_JMPREL:   e->jmprel = d->d_un.d_ptr; break;
                case DT_PLTRELSZ: e->pltrelsz = d->d_un.d_val; break;
                case DT_PLTREL:   e->pltreltype = d->d_un.d_val; break;
                case DT_RELA:     e->rela = d->d_un.d_ptr; break;
                case DT_RELASZ:   e->relasz = d->d_un.d_val; break;
                case DT_REL:      e->rel = d->d_un.d_ptr; break;
                case DT_RELSZ:    e->relsz = d->d_un.d_val; break;
                case DT_NEEDED:
                    if (pass == 1 && e->needed_count < ELF_MAX_NEEDED) {
                        uint64_t off = d->d_un.d_val;
                        if (strtab_vaddr && off < e->strsz)
                            e->needed[e->needed_count++] =
                                get_ptr(e, strtab_vaddr + off, 1);
                    }
                    break;
                }
            }
        } else {
            for (size_t i = 0;; i++) {
                Elf32_Dyn *d = (Elf32_Dyn *)(dyn + i * sizeof(Elf32_Dyn));
                if ((const unsigned char *)d + sizeof(*d) > e->base + e->size)
                    break;
                if (d->d_tag == DT_NULL)
                    break;
                switch (d->d_tag) {
                case DT_STRTAB:   strtab_vaddr = d->d_un.d_ptr; break;
                case DT_STRSZ:    e->strsz = d->d_un.d_val; break;
                case DT_SYMTAB:   e->symtab = get_ptr(e, d->d_un.d_ptr, sizeof(Elf32_Sym)); break;
                case DT_SYMENT:   e->syment = d->d_un.d_val; break;
                case DT_RPATH:    rpath_off = d->d_un.d_val; break;
                case DT_RUNPATH:  runpath_off = d->d_un.d_val; break;
                case DT_JMPREL:   e->jmprel = d->d_un.d_ptr; break;
                case DT_PLTRELSZ: e->pltrelsz = d->d_un.d_val; break;
                case DT_PLTREL:   e->pltreltype = d->d_un.d_val; break;
                case DT_RELA:     e->rela = d->d_un.d_ptr; break;
                case DT_RELASZ:   e->relasz = d->d_un.d_val; break;
                case DT_REL:      e->rel = d->d_un.d_ptr; break;
                case DT_RELSZ:    e->relsz = d->d_un.d_val; break;
                case DT_NEEDED:
                    if (pass == 1 && e->needed_count < ELF_MAX_NEEDED) {
                        uint32_t off = d->d_un.d_val;
                        if (strtab_vaddr && off < e->strsz)
                            e->needed[e->needed_count++] =
                                get_ptr(e, strtab_vaddr + off, 1);
                    }
                    break;
                }
            }
        }
    }

    if (strtab_vaddr)
        e->strtab = get_ptr(e, strtab_vaddr, e->strsz ? e->strsz : 1);
    if (e->strtab) {
        if (rpath_off && rpath_off < e->strsz)
            e->rpath = e->strtab + rpath_off;
        if (runpath_off && runpath_off < e->strsz)
            e->runpath = e->strtab + runpath_off;
    }

    if (e->strtab && e->symtab && e->syment) {
        size_t sym_off = (size_t)((const unsigned char *)e->symtab - e->base);
        size_t strtab_off = (size_t)(e->strtab - (const char *)e->base);
        size_t limit = (strtab_off > sym_off) ? strtab_off : e->size;
        size_t end = sym_off;
        while (end + e->syment <= limit) {
            bool ok;
            if (e->is64) {
                Elf64_Sym *s = (Elf64_Sym *)(e->base + end);
                ok = s->st_name < e->strsz;
            } else {
                Elf32_Sym *s = (Elf32_Sym *)(e->base + end);
                ok = s->st_name < e->strsz;
            }
            if (!ok)
                break;
            end += e->syment;
        }
        e->symcount = (end - sym_off) / e->syment;
    }
}

bool elf_load_file(struct elf_file *e, const char *path)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->path, sizeof(e->path), "%s", path);
    void *p = mmap_file(path, &e->size);
    if (!p)
        return false;
    e->base = p;
    if (memcmp(e->base, ELFMAG, SELFMAG) != 0) {
        munmap((void *)e->base, e->size);
        return false;
    }
    if (e->base[EI_CLASS] == ELFCLASS64) {
        e->is64 = true;
        e->eh64 = (Elf64_Ehdr *)e->base;
        if (e->eh64->e_phoff + (size_t)e->eh64->e_phnum * e->eh64->e_phentsize > e->size) {
            munmap((void *)e->base, e->size);
            return false;
        }
    } else if (e->base[EI_CLASS] == ELFCLASS32) {
        e->is64 = false;
        e->eh32 = (Elf32_Ehdr *)e->base;
        if (e->eh32->e_phoff + (size_t)e->eh32->e_phnum * e->eh32->e_phentsize > e->size) {
            munmap((void *)e->base, e->size);
            return false;
        }
    } else {
        munmap((void *)e->base, e->size);
        return false;
    }
    parse_dynamic(e);
    return true;
}

void elf_unload(struct elf_file *e)
{
    munmap((void *)e->base, e->size);
}

size_t elf_sym_count(const struct elf_file *e)
{
    return e->symcount;
}

const char *elf_sym_name(const struct elf_file *e, size_t idx)
{
    if (idx >= e->symcount)
        return NULL;
    if (e->is64) {
        Elf64_Sym *s = (Elf64_Sym *)(e->symtab + idx * e->syment);
        if (!e->strtab || s->st_name >= e->strsz)
            return NULL;
        return e->strtab + s->st_name;
    } else {
        Elf32_Sym *s = (Elf32_Sym *)(e->symtab + idx * e->syment);
        if (!e->strtab || s->st_name >= e->strsz)
            return NULL;
        return e->strtab + s->st_name;
    }
}

bool elf_sym_defined(const struct elf_file *e, size_t idx)
{
    if (idx >= e->symcount)
        return false;
    if (e->is64) {
        Elf64_Sym *s = (Elf64_Sym *)(e->symtab + idx * e->syment);
        return s->st_shndx != SHN_UNDEF && s->st_value != 0 && s->st_name != 0;
    } else {
        Elf32_Sym *s = (Elf32_Sym *)(e->symtab + idx * e->syment);
        return s->st_shndx != SHN_UNDEF && s->st_value != 0 && s->st_name != 0;
    }
}

uint64_t elf_sym_value(const struct elf_file *e, size_t idx)
{
    if (idx >= e->symcount)
        return 0;
    if (e->is64) {
        Elf64_Sym *s = (Elf64_Sym *)(e->symtab + idx * e->syment);
        return s->st_value;
    } else {
        Elf32_Sym *s = (Elf32_Sym *)(e->symtab + idx * e->syment);
        return s->st_value;
    }
}

uint16_t elf_sym_shndx(const struct elf_file *e, size_t idx)
{
    if (idx >= e->symcount)
        return SHN_UNDEF;
    if (e->is64) {
        Elf64_Sym *s = (Elf64_Sym *)(e->symtab + idx * e->syment);
        return s->st_shndx;
    } else {
        Elf32_Sym *s = (Elf32_Sym *)(e->symtab + idx * e->syment);
        return s->st_shndx;
    }
}

const char *elf_sym_name_by_rva(const struct elf_file *e, uint64_t vaddr,
                                uint64_t *symval)
{
    for (size_t i = 0; i < e->symcount; i++) {
        if (!elf_sym_defined(e, i))
            continue;
        uint64_t v = elf_sym_value(e, i);
        if (v == vaddr) {
            const char *n = elf_sym_name(e, i);
            if (n) {
                if (symval)
                    *symval = v;
                return n;
            }
        }
    }
    return NULL;
}
