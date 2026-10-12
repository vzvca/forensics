/*
 * symfind - locate the shared library that defines a given symbol among
 * the dependencies (transitive included) of an ELF executable or library.
 *
 * Usage: symfind <elf-file> <symbol>
 *
 * Reads ELF files directly from disk (no libelf dependency). Resolves
 * DT_NEEDED entries using RPATH/RUNPATH, LD_LIBRARY_PATH and the default
 * system directories, then walks the whole dependency closure looking for
 * a defined dynamic symbol matching <symbol>.
 */

#include <dirent.h>
#include <elf.h>
#include <fnmatch.h>
#include <regex.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_DEPS 4096

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

enum match_mode {
    MATCH_EXACT,
    MATCH_GLOB,
    MATCH_REGEX,
};

struct matcher {
    enum match_mode mode;
    const char *pattern;
    regex_t regex;
};
static const char *dirname_of_self(void);
static const char *platform_string(void);

struct elf_file {
    char path[PATH_MAX];
    unsigned char ident[EI_NIDENT];
    bool is64;
    bool little;
    const unsigned char *base;
    size_t size;
    Elf64_Ehdr *eh64;
    Elf32_Ehdr *eh32;
    const char *strtab;
    size_t strsz;
    const char *symtab;
    size_t syment;
    size_t symcount;
    const char *needed[MAX_DEPS];
    int needed_count;
    char *rpath;
    char *runpath;
};

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p)
        die("out of memory");
    return p;
}

static char *xstrdup(const char *s)
{
    char *p = xmalloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}

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
            Elf64_Phdr *ph = (Elf64_Phdr *)(e->base + e->eh64->e_phoff + i * e->eh64->e_phentsize);
            if (ph->p_type == PT_LOAD && vaddr >= ph->p_vaddr &&
                vaddr < ph->p_vaddr + ph->p_filesz)
                return (size_t)(vaddr - ph->p_vaddr + ph->p_offset);
        }
    } else {
        for (int i = 0; i < e->eh32->e_phnum; i++) {
            Elf32_Phdr *ph = (Elf32_Phdr *)(e->base + e->eh32->e_phoff + i * e->eh32->e_phentsize);
            if (ph->p_type == PT_LOAD && vaddr >= ph->p_vaddr &&
                vaddr < ph->p_vaddr + ph->p_filesz)
                return (size_t)(vaddr - ph->p_vaddr + ph->p_offset);
        }
    }
    return 0;
}

static const char *get_dyn_ptr(const struct elf_file *e, uint64_t vaddr, uint64_t size)
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
            Elf64_Phdr *ph = (Elf64_Phdr *)(e->base + e->eh64->e_phoff + i * e->eh64->e_phentsize);
            if (ph->p_type == PT_DYNAMIC) {
                size_t off = (size_t)ph->p_offset;
                if (off + ph->p_filesz <= e->size)
                    dyn = e->base + off;
                break;
            }
        }
    } else {
        for (int i = 0; i < e->eh32->e_phnum; i++) {
            Elf32_Phdr *ph = (Elf32_Phdr *)(e->base + e->eh32->e_phoff + i * e->eh32->e_phentsize);
            if (ph->p_type == PT_DYNAMIC) {
                size_t off = (size_t)ph->p_offset;
                if (off + ph->p_filesz <= e->size)
                    dyn = e->base + off;
                break;
            }
        }
    }

    if (!dyn)
        die("%s: no dynamic section", e->path);

    uint64_t strtab_vaddr = 0;
    uint64_t dt_rpath_off = 0, dt_runpath_off = 0;

    for (int pass = 0; pass < 2; pass++) {
    if (e->is64) {
        for (size_t i = 0; ; i++) {
            Elf64_Dyn *d = (Elf64_Dyn *)(dyn + i * sizeof(Elf64_Dyn));
            if ((const unsigned char *)d + sizeof(*d) > e->base + e->size)
                break;
            if (d->d_tag == DT_NULL)
                break;
            switch (d->d_tag) {
            case DT_STRTAB: strtab_vaddr = d->d_un.d_ptr; break;
            case DT_STRSZ:  e->strsz = d->d_un.d_val; break;
            case DT_SYMTAB: e->symtab = get_dyn_ptr(e, d->d_un.d_ptr, sizeof(Elf64_Sym)); break;
            case DT_SYMENT: e->syment = d->d_un.d_val; break;
            case DT_RPATH:  dt_rpath_off = d->d_un.d_val; break;
            case DT_RUNPATH: dt_runpath_off = d->d_un.d_val; break;
            case DT_NEEDED:
                if (pass == 1 && e->needed_count < MAX_DEPS) {
                    uint64_t off = d->d_un.d_val;
                    if (strtab_vaddr && off < e->strsz)
                        e->needed[e->needed_count++] = get_dyn_ptr(e, strtab_vaddr + off, 1);
                }
                break;
            }
        }
    } else {
        for (size_t i = 0; ; i++) {
            Elf32_Dyn *d = (Elf32_Dyn *)(dyn + i * sizeof(Elf32_Dyn));
            if ((const unsigned char *)d + sizeof(*d) > e->base + e->size)
                break;
            if (d->d_tag == DT_NULL)
                break;
            switch (d->d_tag) {
            case DT_STRTAB: strtab_vaddr = d->d_un.d_ptr; break;
            case DT_STRSZ:  e->strsz = d->d_un.d_val; break;
            case DT_SYMTAB: e->symtab = get_dyn_ptr(e, d->d_un.d_ptr, sizeof(Elf32_Sym)); break;
            case DT_SYMENT: e->syment = d->d_un.d_val; break;
            case DT_RPATH:  dt_rpath_off = d->d_un.d_val; break;
            case DT_RUNPATH: dt_runpath_off = d->d_un.d_val; break;
            case DT_NEEDED:
                if (pass == 1 && e->needed_count < MAX_DEPS) {
                    uint32_t off = d->d_un.d_val;
                    if (strtab_vaddr && off < e->strsz)
                        e->needed[e->needed_count++] = get_dyn_ptr(e, strtab_vaddr + off, 1);
                }
                break;
            }
        }
    }
    }

    if (strtab_vaddr)
        e->strtab = get_dyn_ptr(e, strtab_vaddr, e->strsz ? e->strsz : 1);
    if (dt_rpath_off && e->strtab && dt_rpath_off < e->strsz)
        e->rpath = (char *)e->strtab + dt_rpath_off;
    if (dt_runpath_off && e->strtab && dt_runpath_off < e->strsz)
        e->runpath = (char *)e->strtab + dt_runpath_off;

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

static bool elf_load(struct elf_file *e, const char *path)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->path, sizeof(e->path), "%s", path);
    void *p = mmap_file(path, &e->size);
    if (!p)
        return false;
    e->base = p;
    memcpy(e->ident, e->base, EI_NIDENT);
    if (memcmp(e->ident, ELFMAG, SELFMAG) != 0) {
        munmap((void *)e->base, e->size);
        return false;
    }
    if (e->ident[EI_CLASS] == ELFCLASS64) {
        e->is64 = true;
        e->eh64 = (Elf64_Ehdr *)e->base;
        if (e->eh64->e_phoff + (size_t)e->eh64->e_phnum * e->eh64->e_phentsize > e->size) {
            munmap((void *)e->base, e->size);
            return false;
        }
    } else if (e->ident[EI_CLASS] == ELFCLASS32) {
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
    e->little = (e->ident[EI_DATA] == ELFDATA2LSB);
    parse_dynamic(e);
    return true;
}

static void elf_unload(struct elf_file *e)
{
    munmap((void *)e->base, e->size);
}

static const char *sym_name(const struct elf_file *e, size_t idx)
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

static bool sym_is_defined(const struct elf_file *e, size_t idx)
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

static bool matcher_init(struct matcher *m, enum match_mode mode, const char *pattern)
{
    m->mode = mode;
    m->pattern = pattern;
    if (mode == MATCH_REGEX) {
        int rc = regcomp(&m->regex, pattern, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            char err[256];
            regerror(rc, &m->regex, err, sizeof(err));
            fprintf(stderr, "symfind: invalid regex '%s': %s\n", pattern, err);
            return false;
        }
    }
    return true;
}

static void matcher_free(struct matcher *m)
{
    if (m->mode == MATCH_REGEX)
        regfree(&m->regex);
}

static bool matcher_match(const struct matcher *m, const char *name)
{
    switch (m->mode) {
    case MATCH_EXACT:
        return strcmp(name, m->pattern) == 0;
    case MATCH_GLOB:
        return fnmatch(m->pattern, name, 0) == 0;
    case MATCH_REGEX:
        return regexec(&m->regex, name, 0, NULL, 0) == 0;
    }
    return false;
}

static bool search_dir(const char *dir, const char *name, char *out, size_t outsz)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    struct dirent *ent;
    bool found = false;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, name) == 0) {
            snprintf(out, outsz, "%s/%s", dir, name);
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

static bool in_list(const char **list, int n, const char *s)
{
    for (int i = 0; i < n; i++)
        if (strcmp(list[i], s) == 0)
            return true;
    return false;
}

static bool try_dirs(const char *pathlist, const char *name, char *out, size_t outsz)
{
    if (!pathlist)
        return false;
    char *tmp = xstrdup(pathlist);
    char *save = NULL;
    bool found = false;
    for (char *tok = strtok_r(tmp, ":", &save); tok;
         tok = strtok_r(NULL, ":", &save)) {
        if (tok[0] == '\0')
            continue;
        if (strchr(tok, '$')) {
            char expanded[PATH_MAX];
            char *src = tok;
            char *dst = expanded;
            while (*src && dst < expanded + sizeof(expanded) - 1) {
                if (src[0] == '$' && src[1] == 'O' && src[2] == 'R' && src[3] == 'I' &&
                    src[4] == 'G' && src[5] == 'I' && src[6] == 'N') {
                    const char *d = dirname_of_self();
                    size_t len = strlen(d);
                    if (dst + len >= expanded + sizeof(expanded))
                        break;
                    memcpy(dst, d, len);
                    dst += len;
                    src += 7;
                } else if (src[0] == '$' && src[1] == 'L' && src[2] == 'I' &&
                           src[3] == 'B') {
                    const char *l = getenv("LD_LIBRARY_PATH");
                    if (l) {
                        size_t len = strlen(l);
                        if (dst + len >= expanded + sizeof(expanded))
                            break;
                        memcpy(dst, l, len);
                        dst += len;
                    }
                    src += 4;
                } else if (src[0] == '$' && src[1] == 'P' && src[2] == 'L' &&
                           src[3] == 'A' && src[4] == 'T' && src[5] == 'F' &&
                           src[6] == 'O' && src[7] == 'R' && src[8] == 'M') {
                    const char *p = platform_string();
                    size_t len = strlen(p);
                    if (dst + len >= expanded + sizeof(expanded))
                        break;
                    memcpy(dst, p, len);
                    dst += len;
                    src += 9;
                } else {
                    *dst++ = *src++;
                }
            }
            *dst = '\0';
            if (search_dir(expanded, name, out, outsz))
                found = true;
        } else {
            if (search_dir(tok, name, out, outsz))
                found = true;
        }
        if (found)
            break;
    }
    free(tmp);
    return found;
}

static const char *g_self_dir = NULL;

static const char *dirname_of_self(void)
{
    if (g_self_dir)
        return g_self_dir;
    static char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) {
        g_self_dir = "/usr/lib";
        return g_self_dir;
    }
    buf[n] = '\0';
    char *slash = strrchr(buf, '/');
    if (slash)
        *slash = '\0';
    else
        strcpy(buf, ".");
    g_self_dir = buf;
    return g_self_dir;
}

static const char *platform_string(void)
{
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "i386";
#elif defined(__aarch64__)
    return "aarch64";
#else
    return "unknown";
#endif
}

static const char *g_ld_paths[] = {
    "/lib", "/usr/lib", "/lib64", "/usr/lib64",
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu",
    "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
    "/usr/local/lib", NULL,
};

static bool resolve_lib(const struct elf_file *parent, const char *name,
                        char *out, size_t outsz)
{
    if (strchr(name, '/')) {
        snprintf(out, outsz, "%s", name);
        return access(out, R_OK) == 0;
    }
    if (parent->runpath && try_dirs(parent->runpath, name, out, outsz))
        return true;
    const char *ldlp = getenv("LD_LIBRARY_PATH");
    if (try_dirs(ldlp, name, out, outsz))
        return true;
    if (parent->rpath && try_dirs(parent->rpath, name, out, outsz))
        return true;
    for (int i = 0; g_ld_paths[i]; i++)
        if (search_dir(g_ld_paths[i], name, out, outsz))
            return true;
    return false;
}

static void print_match(const char *libpath, const char *symname)
{
    printf("%s: %s\n", libpath, symname);
}

static bool walk(const char *path, const struct matcher *m,
                 const char **visited, int *nvisited, int depth)
{
    struct elf_file e;
    if (!elf_load(&e, path)) {
        fprintf(stderr, "symfind: cannot open or parse %s\n", path);
        return false;
    }
    bool found = false;
    for (size_t i = 0; i < e.symcount; i++) {
        if (!sym_is_defined(&e, i))
            continue;
        const char *n = sym_name(&e, i);
        if (n && matcher_match(m, n)) {
            print_match(e.path, n);
            found = true;
        }
    }
    if (depth < 32) {
        for (int i = 0; i < e.needed_count; i++) {
            const char *dep = e.needed[i];
            if (!dep || in_list(visited, *nvisited, dep))
                continue;
            char libpath[PATH_MAX];
            if (!resolve_lib(&e, dep, libpath, sizeof(libpath))) {
                fprintf(stderr, "symfind: cannot resolve %s (needed by %s)\n",
                        dep, e.path);
                continue;
            }
            visited[(*nvisited)++] = xstrdup(dep);
            if (walk(libpath, m, visited, nvisited, depth + 1))
                found = true;
        }
    }
    elf_unload(&e);
    return found;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] <elf-file> <pattern>\n"
        "\n"
        "Options:\n"
        "  -g  treat <pattern> as a shell glob (fnmatch, e.g. 'pri*')\n"
        "  -r  treat <pattern> as an extended regular expression (POSIX ERE)\n"
        "\n"
        "By default <pattern> is matched literally. Matches are printed as\n"
        "'<library>: <symbol>' for every defined symbol in the file and its\n"
        "transitive dependencies. Exit code is 0 if at least one symbol\n"
        "matched, 1 otherwise, 2 on usage or file error.\n",
        prog);
}

int main(int argc, char **argv)
{
    enum match_mode mode = MATCH_EXACT;
    int opt;
    while ((opt = getopt(argc, argv, "gr")) != -1) {
        switch (opt) {
        case 'g': mode = MATCH_GLOB; break;
        case 'r': mode = MATCH_REGEX; break;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    if (argc - optind != 2) {
        usage(argv[0]);
        return 2;
    }
    const char *file = argv[optind];
    const char *pattern = argv[optind + 1];

    struct stat st;
    if (stat(file, &st) < 0)
        die("symfind: %s: %s", file, strerror(errno));

    struct matcher m;
    if (!matcher_init(&m, mode, pattern))
        return 2;

    const char *visited[MAX_DEPS];
    int nvisited = 0;
    visited[nvisited++] = xstrdup(file);

    bool found = walk(file, &m, visited, &nvisited, 0);
    matcher_free(&m);
    if (!found) {
        printf("no symbol matching '%s' found in %s or its dependencies\n",
               pattern, file);
        return 1;
    }
    return 0;
}
