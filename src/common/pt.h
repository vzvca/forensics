#ifndef PT_H
#define PT_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

int pt_attach(pid_t pid);
int pt_detach(pid_t pid, int sig);
int pt_cont(pid_t pid, int sig);
int pt_getregs(pid_t pid, struct user_regs_struct *regs);
int pt_setregs(pid_t pid, const struct user_regs_struct *regs);
int pt_peek(pid_t pid, uint64_t addr, uint64_t *word);
int pt_poke(pid_t pid, uint64_t addr, uint64_t word);
int pt_read_mem(pid_t pid, uint64_t addr, void *buf, size_t len);
int pt_write_mem(pid_t pid, uint64_t addr, const void *buf, size_t len);
int pt_read_str(pid_t pid, uint64_t addr, char *buf, size_t maxlen);
int pt_wait(pid_t pid, int *status);

#endif
