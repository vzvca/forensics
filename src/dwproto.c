/*
 * dwproto - extract function prototypes from DWARF debug information and
 * print them in the same textual shape as src/prototypes.h entries.
 *
 * Usage: dwproto <elf-file> [function ...]
 *
 * Without function names, every function with debug info is listed.
 * With names, only those are printed. If the file itself carries no
 * debug info, the .gnu_debuglink companion is tried (same directory,
 * .debug/ subdirectory, /usr/lib/debug/...).
 */

#include "dwarg.h"
#include "prototypes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *arg_char(enum arg_type t)
{
    switch (t) {
    case TYPE_INTEGER:  return "TYPE_INTEGER";
    case TYPE_UNSIGNED: return "TYPE_UNSIGNED";
    case TYPE_POINTER:  return "TYPE_POINTER";
    case TYPE_STRING:   return "TYPE_STRING";
    case TYPE_DOUBLE:   return "TYPE_DOUBLE";
    case TYPE_FLOAT:    return "TYPE_FLOAT";
    case TYPE_CHAR:     return "TYPE_CHAR";
    case TYPE_BYTES:    return "TYPE_BYTES";
    default:            return "TYPE_END";
    }
}

static const char *ret_char(enum ret_type r)
{
    switch (r) {
    case RET_INT:      return "RET_INT";
    case RET_UNSIGNED: return "RET_UNSIGNED";
    case RET_POINTER:  return "RET_POINTER";
    case RET_STRING:   return "RET_STRING";
    case RET_DOUBLE:   return "RET_DOUBLE";
    case RET_FLOAT:    return "RET_FLOAT";
    default:           return "RET_NONE";
    }
}

static void print_proto(const char *name, const enum arg_type args[8],
                        enum ret_type ret, const char *pretty)
{
    printf("    { \"%s\", %s, { ", name, ret_char(ret));
    for (int i = 0; i < 8 && args[i] != TYPE_END; i++)
        printf("%s, ", arg_char(args[i]));
    printf("TYPE_END } },   /* %s */\n", pretty);
}

static bool list_cb(const char *name, const enum arg_type args[8],
                    enum ret_type ret, const char *pretty, void *user)
{
    (void)user;
    print_proto(name, args, ret, pretty);
    return true;
}

static bool try_file(const char *file, char **names, int nnames)
{
    if (nnames == 0) {
        if (!dwarf_list_prototypes(file, list_cb, NULL)) {
            fprintf(stderr, "dwproto: %s: no usable debug info\n", file);
            return false;
        }
        return true;
    }
    bool all = true;
    for (int i = 0; i < nnames; i++) {
        enum arg_type args[8];
        enum ret_type ret;
        char pretty[256];
        if (dwarf_func_prototype(file, names[i], args, &ret, pretty))
            print_proto(names[i], args, ret, pretty);
        else {
            printf("    /* %s: not found in %s */\n", names[i], file);
            all = false;
        }
    }
    return all;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf-file> [function ...]\n", argv[0]);
        fprintf(stderr, "Without function names, lists every function "
                        "found in the debug info.\n");
        return 2;
    }

    const char *file = argv[1];
    char **names = &argv[2];
    int nnames = argc - 2;

    if (try_file(file, names, nnames))
        return 0;

    uint32_t crc;
    char *link = dwarf_debuglink(file, &crc);
    if (!link) {
        fprintf(stderr, "dwproto: %s: no debug info and no .gnu_debuglink\n",
                file);
        return 1;
    }
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s", file);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    else
        strcpy(dir, ".");
    const char *sufs[] = { "%s/%s", "%s/.debug/%s", "/usr/lib/debug%s/%s", NULL };
    for (int i = 0; sufs[i]; i++) {
        char cand[4096];
        snprintf(cand, sizeof(cand), sufs[i], dir, link);
        if (access(cand, R_OK) == 0) {
            bool ok = try_file(cand, names, nnames);
            free(link);
            return ok ? 0 : 1;
        }
    }
    fprintf(stderr, "dwproto: %s: debug file '%s' not found\n", file, link);
    free(link);
    return 1;
}
