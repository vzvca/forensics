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

struct func_prototype {
    const char *name;
    enum arg_type args[8];
};

/*
 * Hard-coded prototype table for common libc functions.
 * Layout: {"name", {arg1, arg2, ..., TYPE_END}}.
 * Classification follows the System V AMD64 ABI: INTEGER-class args
 * consume rdi, rsi, rdx, rcx, r8, r9 then the stack; SSE-class args
 * consume xmm0..xmm7.
 */
static const struct func_prototype prototypes[] = {
    { "malloc",        { TYPE_UNSIGNED, TYPE_END } },
    { "calloc",        { TYPE_UNSIGNED, TYPE_UNSIGNED, TYPE_END } },
    { "realloc",       { TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "free",          { TYPE_POINTER, TYPE_END } },
    { "memcpy",        { TYPE_POINTER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "memset",        { TYPE_POINTER, TYPE_INTEGER, TYPE_UNSIGNED, TYPE_END } },
    { "memcmp",        { TYPE_POINTER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "strlen",        { TYPE_STRING, TYPE_END } },
    { "strcmp",        { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "strncmp",       { TYPE_STRING, TYPE_STRING, TYPE_UNSIGNED, TYPE_END } },
    { "strcpy",        { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "strncpy",       { TYPE_POINTER, TYPE_STRING, TYPE_UNSIGNED, TYPE_END } },
    { "strcat",        { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "strdup",        { TYPE_STRING, TYPE_END } },
    { "strchr",        { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "strstr",        { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "open",          { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "open64",        { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "close",         { TYPE_INTEGER, TYPE_END } },
    { "read",          { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "write",         { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "fopen",         { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "fopen64",       { TYPE_STRING, TYPE_STRING, TYPE_END } },
    { "fclose",        { TYPE_POINTER, TYPE_END } },
    { "fread",         { TYPE_POINTER, TYPE_UNSIGNED, TYPE_UNSIGNED, TYPE_POINTER, TYPE_END } },
    { "fwrite",        { TYPE_POINTER, TYPE_UNSIGNED, TYPE_UNSIGNED, TYPE_POINTER, TYPE_END } },
    { "fgets",         { TYPE_POINTER, TYPE_INTEGER, TYPE_POINTER, TYPE_END } },
    { "fprintf",       { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "printf",        { TYPE_STRING, TYPE_END } },
    { "sprintf",       { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "snprintf",      { TYPE_POINTER, TYPE_UNSIGNED, TYPE_STRING, TYPE_END } },
    { "puts",          { TYPE_STRING, TYPE_END } },
    { "gets",          { TYPE_POINTER, TYPE_END } },
    { "putchar",       { TYPE_INTEGER, TYPE_END } },
    { "getchar",       { TYPE_END } },
    { "atoi",          { TYPE_STRING, TYPE_END } },
    { "atol",          { TYPE_STRING, TYPE_END } },
    { "exit",          { TYPE_INTEGER, TYPE_END } },
    { "abort",         { TYPE_END } },
    { "getenv",        { TYPE_STRING, TYPE_END } },
    { "setenv",        { TYPE_STRING, TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "socket",        { TYPE_INTEGER, TYPE_INTEGER, TYPE_INTEGER, TYPE_END } },
    { "connect",       { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "bind",          { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_END } },
    { "listen",        { TYPE_INTEGER, TYPE_INTEGER, TYPE_END } },
    { "accept",        { TYPE_INTEGER, TYPE_POINTER, TYPE_POINTER, TYPE_END } },
    { "send",          { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_INTEGER, TYPE_END } },
    { "recv",          { TYPE_INTEGER, TYPE_POINTER, TYPE_UNSIGNED, TYPE_INTEGER, TYPE_END } },
    { "gettimeofday",  { TYPE_POINTER, TYPE_POINTER, TYPE_END } },
    { "time",          { TYPE_POINTER, TYPE_END } },
    { "sleep",         { TYPE_UNSIGNED, TYPE_END } },
    { "usleep",        { TYPE_UNSIGNED, TYPE_END } },
    { "getpid",        { TYPE_END } },
    { "pthread_create", { TYPE_POINTER, TYPE_POINTER, TYPE_POINTER, TYPE_POINTER, TYPE_END } },
    { "pthread_join",  { TYPE_UNSIGNED, TYPE_POINTER, TYPE_END } },
    { "pthread_mutex_lock",   { TYPE_POINTER, TYPE_END } },
    { "pthread_mutex_unlock", { TYPE_POINTER, TYPE_END } },
    { "dlopen",        { TYPE_STRING, TYPE_INTEGER, TYPE_END } },
    { "dlsym",         { TYPE_POINTER, TYPE_STRING, TYPE_END } },
    { "system",        { TYPE_STRING, TYPE_END } },
    { NULL,             { TYPE_END } },
};

static const enum arg_type *proto_lookup(const char *name)
{
    if (!name)
        return NULL;
    for (const struct func_prototype *p = prototypes; p->name; p++)
        if (strcmp(p->name, name) == 0)
            return p->args;
    return NULL;
}

#endif
