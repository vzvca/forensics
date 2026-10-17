#include "pt.h"

#include <errno.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int pt_attach(pid_t pid) { return ptrace(PTRACE_ATTACH, pid, NULL, NULL); }

int pt_detach(pid_t pid, int sig) {
  return ptrace(PTRACE_DETACH, pid, NULL, (void *)(long)sig);
}

int pt_cont(pid_t pid, int sig) {
  return ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig);
}

int pt_getregs(pid_t pid, struct user_regs_struct *regs) {
  return ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

int pt_setregs(pid_t pid, const struct user_regs_struct *regs) {
  return ptrace(PTRACE_SETREGS, pid, NULL, (void *)regs);
}

int pt_peek(pid_t pid, uint64_t addr, uint64_t *word) {
  errno = 0;
  long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
  if (v == -1 && errno) return -1;
  *word = (uint64_t)(unsigned long)v;
  return 0;
}

int pt_poke(pid_t pid, uint64_t addr, uint64_t word) {
  long v = ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)(long)word);
  return v == -1 ? -1 : 0;
}

int pt_read_mem(pid_t pid, uint64_t addr, void *buf, size_t len) {
  unsigned char *dst = buf;
  size_t done = 0;
  while (done < len) {
    uint64_t word;
    size_t chunk = sizeof(word) - (addr % sizeof(word));
    if (chunk > len - done) chunk = len - done;
    if (pt_peek(pid, addr & ~(uint64_t)7, &word) < 0) return -1;
    for (size_t i = 0; i < chunk; i++) dst[done + i] = ((unsigned char *)&word)[addr % sizeof(word) + i];
    done += chunk;
    addr += chunk;
  }
  return 0;
}

int pt_write_mem(pid_t pid, uint64_t addr, const void *buf, size_t len) {
  const unsigned char *src = buf;
  size_t done = 0;
  while (done < len) {
    uint64_t aligned = addr & ~(uint64_t)7;
    uint64_t word;
    size_t off = addr % sizeof(word);
    size_t chunk = sizeof(word) - off;
    if (chunk > len - done) chunk = len - done;
    if (off != 0 || chunk != sizeof(word)) {
      if (pt_peek(pid, aligned, &word) < 0) return -1;
    }
    for (size_t i = 0; i < chunk; i++)
      ((unsigned char *)&word)[off + i] = src[done + i];
    if (pt_poke(pid, aligned, word) < 0) return -1;
    done += chunk;
    addr += chunk;
  }
  return 0;
}

int pt_read_str(pid_t pid, uint64_t addr, char *buf, size_t maxlen) {
  size_t i = 0;
  while (i < maxlen - 1) {
    uint64_t word;
    if (pt_peek(pid, (addr + i) & ~(uint64_t)7, &word) < 0) return -1;
    unsigned char *w = (unsigned char *)&word;
    for (size_t j = (addr + i) % 8; j < 8 && i < maxlen - 1; j++, i++) {
      buf[i] = w[j];
      if (w[j] == '\0') return 0;
    }
  }
  buf[maxlen - 1] = '\0';
  return 0;
}

int pt_wait(pid_t pid, int *status) {
  int st;
  if (waitpid(pid, &st, 0) < 0) return -1;
  if (status) *status = st;
  return 0;
}
