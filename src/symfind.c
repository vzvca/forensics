/*
 * symfind - locate the shared library that defines a given symbol among
 * the dependencies (transitive included) of an ELF executable or library.
 *
 * Usage: symfind [-g|-r] <elf-file> <pattern>
 *
 * -g: shell glob (fnmatch), -r: POSIX ERE regex, default: exact match.
 */

#include "elfparse.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_DEPS 4096

static const char *dirname_of_self(void);
static const char *platform_string(void);

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

static bool walk(const char *path, const struct matcher *m,
                 const char **visited, int *nvisited, int depth)
{
    struct elf_file e;
    if (!elf_load_file(&e, path)) {
        fprintf(stderr, "symfind: cannot open or parse %s\n", path);
        return false;
    }
    bool found = false;
    for (size_t i = 0; i < elf_sym_count(&e); i++) {
        if (!elf_sym_defined(&e, i))
            continue;
        const char *n = elf_sym_name(&e, i);
        if (n && matcher_match(m, n)) {
            printf("%s: %s\n", e.path, n);
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
