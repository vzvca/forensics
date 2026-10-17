#ifndef TARGET_H
#define TARGET_H

#include "elfparse.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TARGET_MAX_MODULES 512
#define TARGET_MAX_THREADS 256

struct target_module {
    char path[PATH_MAX];
    uint64_t base;
};

struct target {
    pid_t pid;
    struct target_module modules[TARGET_MAX_MODULES];
    int nmodules;
    pid_t threads[TARGET_MAX_THREADS];
    int nthreads;
    bool launched;
};

struct target_slot {
    uint64_t addr;
    uint64_t orig;
};

void target_init(struct target *t, pid_t pid);
void target_load_maps(struct target *t);
int target_find_module(struct target *t, const char *path);
bool target_range_mapped(struct target *t, uint64_t addr);

int target_slot_is_reloc(uint64_t type);
int target_find_got_slots(struct target *t, const char *symbol,
                           struct target_slot *slots, int max);

int target_module_sym(struct target *t, const char *symbol,
                      char defining[PATH_MAX]);

uint64_t target_resolve_addr(struct target *t, const char *symbol,
                             char defining[PATH_MAX]);

#endif
