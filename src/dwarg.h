#ifndef FORENSICS_DWARG_H
#define FORENSICS_DWARG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "prototypes.h"

/*
 * Extract a function prototype from the DWARF debug information of an
 * ELF file. Only .debug_info/.debug_abbrev/.debug_str/.debug_line_str
 * are parsed (DWARF 4 and 5, 32- and 64-bit formats, as emitted by
 * gcc/clang -g). Returns true and fills args/ret if the symbol is found
 * with a usable prototype; args is terminated by TYPE_END (max 8).
 */
bool dwarf_func_prototype(const char *elf_path, const char *func_name,
                          enum arg_type args[8], enum ret_type *ret,
                          char pretty[256]);

char *dwarf_debuglink(const char *elf_path, uint32_t *crc);

#endif
