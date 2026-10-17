#ifndef FORENSICS_PROTOTYPES_H
#define FORENSICS_PROTOTYPES_H

#include <stddef.h>
#include <string.h>

enum arg_type {
    TYPE_END = 0,
    TYPE_INTEGER,
    TYPE_UNSIGNED,
    TYPE_POINTER,
    TYPE_STRING,
    TYPE_DOUBLE,
    TYPE_FLOAT,
    TYPE_CHAR,
    TYPE_BYTES,
};

enum ret_type {
    RET_NONE = 0,
    RET_INT,
    RET_UNSIGNED,
    RET_POINTER,
    RET_STRING,
    RET_DOUBLE,
    RET_FLOAT,
};

struct func_prototype {
    const char *name;
    enum ret_type ret;
    enum arg_type args[8];
};

/*
 * Hard-coded prototype table for common libc functions.
 * Layout: {"name", RET, {arg1, arg2, ..., TYPE_END}}.
 * Argument and return classification follows the System V AMD64 ABI:
 * INTEGER-class args consume rdi, rsi, rdx, rcx, r8, r9 then the stack;
 * SSE-class args consume xmm0..xmm7. Returns use rax (+rdx) or xmm0.
 */
static const struct func_prototype prototypes[] = {
    { "malloc",        RET_POINTER, { TYPE_UNSIGNED, TYPE_END } },
    { "calloc",        RET_POINTER, { TYPE_UNSIGNED, TYPE_UNSIGNED, TYPE_END } },
    { "realloc",       RET_POINTER, { TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "free",          RET_NONE,    { TYPE_POINTER, TYPE_END } },
    { "memcpy",        RET_POINTER, { TYPE_POINTER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "memset",        RET_POINTER, { TYPE_POINTER, TYPE_INTEGER, TYPE_UNSIGNED, TYPE_END } },
    { "memcmp",        RET_INT,     { TYPE_POINTER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "strlen",        RET_UNSIGNED, { TYPE_STRING, TYPE_END } },
    { "strcmp",        RET_INT,     { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "strncmp",       RET_INT,     { TYPE_STRING, TYPE_STRING, TYPE_UNSIGNED, TYPE_END } },
    { "strcpy",        RET_POINTER, { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "strncpy",       RET_POINTER, { TYPE_POINTER, TYPE_STRING, TYPE_UNSIGNED, TYPE_END } },
    { "strcat",        RET_POINTER, { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "strdup",        RET_STRING,  { TYPE_STRING, TYPE_END } },
    { "strchr",        RET_POINTER, { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "strstr",        RET_POINTER, { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "open",          RET_INT,     { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "open64",        RET_INT,     { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "close",         RET_INT,     { TYPE_INTEGER, TYPE_END } },
    { "read",          RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "write",         RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "fopen",         RET_POINTER, { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "fopen64",       RET_POINTER, { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "fclose",        RET_INT,     { TYPE_POINTER, TYPE_END } },
    { "fread",         RET_UNSIGNED, { TYPE_POINTER, TYPE_UNSIGNED, TYPE_UNSIGNED, TYPE_POINTER, TYPE_END } },
    { "fwrite",        RET_UNSIGNED, { TYPE_POINTER, TYPE_UNSIGNED, TYPE_UNSIGNED, TYPE_POINTER, TYPE_END } },
    { "fgets",         RET_STRING,  { TYPE_POINTER, TYPE_INTEGER, TYPE_POINTER, TYPE_END } },
    { "fprintf",       RET_INT,     { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "printf",        RET_INT,     { TYPE_STRING, TYPE_END } },
    { "sprintf",       RET_INT,     { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "snprintf",      RET_INT,     { TYPE_POINTER, TYPE_UNSIGNED, TYPE_STRING, TYPE_END } },
    { "puts",          RET_INT,     { TYPE_STRING, TYPE_END } },
    { "putchar",       RET_INT,     { TYPE_INTEGER, TYPE_END } },
    { "getchar",       RET_INT,     { TYPE_END } },
    { "atoi",          RET_INT,     { TYPE_STRING, TYPE_END } },
    { "atol",          RET_INT,     { TYPE_STRING, TYPE_END } },
    { "exit",          RET_NONE,    { TYPE_INTEGER, TYPE_END } },
    { "abort",         RET_NONE,    { TYPE_END } },
    { "getenv",        RET_STRING,  { TYPE_STRING, TYPE_END } },
    { "setenv",        RET_INT,     { TYPE_STRING, TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "socket",        RET_INT,     { TYPE_INTEGER, TYPE_INTEGER, TYPE_INTEGER, TYPE_END } },
    { "connect",       RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "bind",          RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "listen",        RET_INT,     { TYPE_INTEGER, TYPE_INTEGER, TYPE_END } },
    { "accept",        RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_POINTER, TYPE_END } },
    { "send",          RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_INTEGER, TYPE_END } },
    { "recv",          RET_INT,     { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_INTEGER, TYPE_END } },
    { "gettimeofday",  RET_INT,     { TYPE_POINTER, TYPE_POINTER, TYPE_END } },
    { "time",          RET_INT,     { TYPE_POINTER, TYPE_END } },
    { "sleep",         RET_UNSIGNED, { TYPE_UNSIGNED, TYPE_END } },
    { "usleep",        RET_INT,     { TYPE_UNSIGNED, TYPE_END } },
    { "getpid",        RET_INT,     { TYPE_END } },
    { "pthread_create", RET_INT,    { TYPE_POINTER, TYPE_POINTER, TYPE_POINTER, TYPE_POINTER, TYPE_END } },
    { "pthread_join",  RET_INT,     { TYPE_UNSIGNED, TYPE_POINTER, TYPE_END } },
    { "pthread_mutex_lock",   RET_INT, { TYPE_POINTER, TYPE_END } },
    { "pthread_mutex_unlock", RET_INT, { TYPE_POINTER, TYPE_END } },
    { "dlopen",        RET_POINTER, { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "dlsym",         RET_POINTER, { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "system",        RET_INT,     { TYPE_STRING, TYPE_END } },
    { NULL,            RET_NONE,    { TYPE_END } },
};

static const struct func_prototype *proto_lookup(const char *name)
{
    if (!name)
        return NULL;
    for (const struct func_prototype *p = prototypes; p->name; p++)
        if (strcmp(p->name, name) == 0)
            return p;
    return NULL;
}

#endif
