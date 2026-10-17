#ifndef REMOTE_H
#define REMOTE_H

#include "pt.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

uint64_t remote_mmap(pid_t tid, uint64_t addr, size_t len, int prot,
                     int flags);

int remote_call(pid_t tid, uint64_t func, const uint64_t args[6],
                uint64_t *retval);
uint64_t remote_dlopen(pid_t tid, const char *path, int mode);
uint64_t remote_dlsym(pid_t tid, uint64_t handle, const char *symbol);

#endif
