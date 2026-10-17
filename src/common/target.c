#include "target.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pt.h"

void target_init(struct target *t, pid_t pid)
{
    memset(t, 0, sizeof(*t));
    t->pid = pid;
}

void target_load_maps(struct target *t)
{
    char mapsfile[64];
    snprintf(mapsfile, sizeof(mapsfile), "/proc/%d/maps", t->pid);
    FILE *f = fopen(mapsfile, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", mapsfile, strerror(errno));
        exit(1);
    }

    char line[PATH_MAX + 128];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end, off;
        char perms[8];
        char path[PATH_MAX];
        path[0] = '\0';
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095s",
                       &start, &end, perms, &off, path);
        (void)end;
        (void)perms;
        if (n < 4)
            continue;
        if (path[0] != '/')
            continue;
        if (off != 0)
            continue;

        char *bang = strstr(path, " (deleted");
        if (bang)
            *bang = '\0';

        int existing = target_find_module(t, path);
        if (existing >= 0) {
            if (start < t->modules[existing].base)
                t->modules[existing].base = start;
            continue;
        }
        if (t->nmodules >= TARGET_MAX_MODULES)
            break;
        snprintf(t->modules[t->nmodules].path, sizeof(t->modules[0].path),
                 "%s", path);
        t->modules[t->nmodules].base = start;
        t->nmodules++;
    }
    fclose(f);
}

int target_find_module(struct target *t, const char *path)
{
    for (int i = 0; i < t->nmodules; i++)
        if (strcmp(t->modules[i].path, path) == 0)
            return i;
    return -1;
}

bool target_range_mapped(struct target *t, uint64_t addr)
{
    char mapsfile[64];
    snprintf(mapsfile, sizeof(mapsfile), "/proc/%d/maps", t->pid);
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

int target_slot_is_reloc(uint64_t type)
{
#if defined(__x86_64__)
    return type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT;
#else
    (void)type;
    return 0;
#endif
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

int target_find_got_slots(struct target *t, const char *symbol,
                          struct target_slot *slots, int max)
{
    int found = 0;

    for (int m = 0; m < t->nmodules; m++) {
        struct elf_file e;
        if (!elf_load_file(&e, t->modules[m].path))
            continue;
        if (!e.is64) {
            elf_unload(&e);
            continue;
        }

        struct { uint64_t addr; uint64_t size; } tables[2] = {
            { e.jmprel, e.pltrelsz },
            { e.rela, e.relasz },
        };

        for (int tb = 0; tb < 2; tb++) {
            if (!tables[tb].addr || !tables[tb].size)
                continue;
            size_t off = vaddr_off(&e, tables[tb].addr);
            if (!off)
                continue;
            size_t entsz = sizeof(Elf64_Rela);
            size_t count = tables[tb].size / entsz;
            for (size_t i = 0; i < count; i++) {
                Elf64_Rela *r = (Elf64_Rela *)(e.base + off + i * entsz);
                uint64_t symidx = ELF64_R_SYM(r->r_info);
                uint64_t type = ELF64_R_TYPE(r->r_info);
                if (!target_slot_is_reloc(type))
                    continue;
                const char *name = elf_sym_name(&e, symidx);
                if (!name || strcmp(name, symbol) != 0)
                    continue;
                uint64_t slotaddr = t->modules[m].base + r->r_offset;
                bool dup = false;
                for (int s = 0; s < found; s++)
                    if (slots[s].addr == slotaddr) {
                        dup = true;
                        break;
                    }
                if (dup || found >= max)
                    continue;
                memset(&slots[found], 0, sizeof(slots[found]));
                slots[found].addr = slotaddr;
                uint64_t orig;
                if (pt_peek(t->pid, slotaddr, &orig) == 0)
                    slots[found].orig = orig;
                found++;
            }
        }
        elf_unload(&e);
    }
    return found;
}

int target_module_sym(struct target *t, const char *symbol,
                      char defining[PATH_MAX])
{
    for (int m = 0; m < t->nmodules; m++) {
        struct elf_file e;
        if (!elf_load_file(&e, t->modules[m].path))
            continue;
        for (size_t s = 0; s < elf_sym_count(&e); s++) {
            const char *n = elf_sym_name(&e, s);
            if (n && strcmp(n, symbol) == 0 && elf_sym_defined(&e, s)) {
                int ok = elf_sym_value(&e, s) != 0;
                if (defining)
                    snprintf(defining, PATH_MAX, "%s", t->modules[m].path);
                elf_unload(&e);
                return ok ? 0 : -1;
            }
        }
        elf_unload(&e);
    }
    return -1;
}

uint64_t target_resolve_addr(struct target *t, const char *symbol,
                             char defining[PATH_MAX])
{
    for (int m = 0; m < t->nmodules; m++) {
        struct elf_file e;
        if (!elf_load_file(&e, t->modules[m].path))
            continue;
        for (size_t s = 0; s < elf_sym_count(&e); s++) {
            const char *n = elf_sym_name(&e, s);
            if (n && strcmp(n, symbol) == 0 && elf_sym_defined(&e, s)) {
                uint64_t v = elf_sym_value(&e, s);
                elf_unload(&e);
                if (v) {
                    if (defining)
                        snprintf(defining, PATH_MAX, "%s", t->modules[m].path);
                    return t->modules[m].base + v;
                }
                return 0;
            }
        }
        elf_unload(&e);
    }
    return 0;
}
