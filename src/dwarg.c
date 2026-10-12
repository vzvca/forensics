#include "dwarg.h"
#include "dwarf_consts.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct dw_file {
    unsigned char *base;
    size_t size;
    const unsigned char *info;
    size_t info_size;
    const unsigned char *abbrev;
    size_t abbrev_size;
    const unsigned char *str;
    size_t str_size;
    const unsigned char *line_str;
    size_t line_str_size;
};

static uint64_t rd_u(const unsigned char **p, int width)
{
    uint64_t v = 0;
    memcpy(&v, *p, width);
    *p += width;
    return v;
}

static uint64_t rd_leb(const unsigned char **p, bool sign)
{
    uint64_t v = 0;
    int shift = 0;
    for (;;) {
        unsigned char b = *(*p)++;
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            if (sign && shift < 64 && (b & 0x40))
                v |= ~0ULL << (shift + 7);
            return v;
        }
        shift += 7;
        if (shift > 70)
            return v;
    }
}

static bool dw_open(struct dw_file *f, const char *path)
{
    memset(f, 0, sizeof(*f));
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return false;
    }
    f->base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (f->base == MAP_FAILED)
        return false;
    f->size = st.st_size;
    if (memcmp(f->base, ELFMAG, SELFMAG) != 0 || f->base[EI_CLASS] != ELFCLASS64)
        return false;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)f->base;
    if (eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > f->size ||
        eh->e_shstrndx >= eh->e_shnum)
        return false;
    Elf64_Shdr *shstr = (Elf64_Shdr *)(f->base + eh->e_shoff +
                                       (size_t)eh->e_shstrndx * eh->e_shentsize);
    if (shstr->sh_offset + shstr->sh_size > f->size)
        return false;
    for (int i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = (Elf64_Shdr *)(f->base + eh->e_shoff + (size_t)i * eh->e_shentsize);
        if (sh->sh_type == SHT_NOBITS || !sh->sh_size ||
            sh->sh_offset + sh->sh_size > f->size || sh->sh_name >= shstr->sh_size)
            continue;
        const char *n = (const char *)(f->base + shstr->sh_offset + sh->sh_name);
        if (strcmp(n, ".debug_info") == 0) {
            f->info = f->base + sh->sh_offset;
            f->info_size = sh->sh_size;
        } else if (strcmp(n, ".debug_abbrev") == 0) {
            f->abbrev = f->base + sh->sh_offset;
            f->abbrev_size = sh->sh_size;
        } else if (strcmp(n, ".debug_str") == 0) {
            f->str = f->base + sh->sh_offset;
            f->str_size = sh->sh_size;
        } else if (strcmp(n, ".debug_line_str") == 0) {
            f->line_str = f->base + sh->sh_offset;
            f->line_str_size = sh->sh_size;
        }
    }
    return f->info && f->abbrev;
}

static void dw_close(struct dw_file *f)
{
    if (f->base)
        munmap(f->base, f->size);
}

struct abbrev_ent {
    uint64_t at;
    uint64_t form;
    uint64_t ic;
};

struct abbrev {
    uint64_t tag;
    bool has_children;
    struct abbrev_ent attrs[24];
    int nattrs;
};

static bool abbrev_at(struct dw_file *f, uint64_t abbrev_off, uint64_t code,
                      struct abbrev *ab)
{
    if (abbrev_off >= f->abbrev_size)
        return false;
    const unsigned char *p = f->abbrev + abbrev_off;
    while (p < f->abbrev + f->abbrev_size) {
        uint64_t c = rd_leb(&p, false);
        if (c == 0)
            return false;
        memset(ab, 0, sizeof(*ab));
        ab->tag = rd_leb(&p, false);
        ab->has_children = *p++ != 0;
        ab->nattrs = 0;
        for (;;) {
            uint64_t at = rd_leb(&p, false);
            uint64_t form = rd_leb(&p, false);
            if (at == 0 && form == 0)
                break;
            uint64_t ic = 0;
            if (form == DW_FORM_implicit_const)
                ic = rd_leb(&p, true);
            if (ab->nattrs < 24) {
                ab->attrs[ab->nattrs].at = at;
                ab->attrs[ab->nattrs].form = form;
                ab->attrs[ab->nattrs].ic = ic;
                ab->nattrs++;
            }
        }
        if (c == code)
            return true;
    }
    return false;
}

static bool attr_get(struct dw_file *f, const unsigned char **p, uint64_t form,
                     uint64_t ic, uint64_t *u, const char **s, bool *is_str)
{
    *u = ic;
    if (s)
        *s = NULL;
    if (is_str)
        *is_str = false;
    switch (form) {
    case DW_FORM_addr: *u = rd_u(p, 8); break;
    case DW_FORM_data1: case DW_FORM_flag: case DW_FORM_ref1:
    case DW_FORM_strx1:
        *u = rd_u(p, 1); break;
    case DW_FORM_data2: case DW_FORM_ref2: case DW_FORM_strx2:
        *u = rd_u(p, 2); break;
    case DW_FORM_data4: case DW_FORM_ref4: case DW_FORM_sec_offset:
        *u = rd_u(p, 4); break;
    case DW_FORM_strp: {
        uint64_t off = rd_u(p, 4);
        *u = off;
        if (f->str && off < f->str_size && s) {
            *s = (const char *)(f->str + off);
            *is_str = true;
        }
        break;
    }
    case DW_FORM_line_strp: {
        uint64_t off = rd_u(p, 4);
        *u = off;
        if (f->line_str && off < f->line_str_size && s) {
            *s = (const char *)(f->line_str + off);
            *is_str = true;
        }
        break;
    }
    case DW_FORM_data8: case DW_FORM_ref8: case DW_FORM_ref_sig8:
        *u = rd_u(p, 8); break;
    case DW_FORM_sdata: *u = rd_leb(p, true); break;
    case DW_FORM_udata: case DW_FORM_ref_udata: case DW_FORM_strx:
        *u = rd_leb(p, false); break;
    case DW_FORM_string:
        if (s) { *s = (const char *)*p; *is_str = true; }
        while (*(*p)++) ;
        break;

    case DW_FORM_block: case DW_FORM_exprloc: {
        uint64_t len = rd_leb(p, false);
        *p += len;
        break;
    }
    case DW_FORM_block1: {
        uint64_t len = rd_u(p, 1);
        *p += len;
        break;
    }
    case DW_FORM_block2: {
        uint64_t len = rd_u(p, 2);
        *p += len;
        break;
    }
    case DW_FORM_block4: {
        uint64_t len = rd_u(p, 4);
        *p += len;
        break;
    }
    case DW_FORM_flag_present: case DW_FORM_implicit_const:
        break;
    default:
        return false;
    }
    return true;
}

static enum arg_type base_to_arg(uint64_t enc, uint64_t bytes)
{
    switch (enc) {
    case DW_ATE_address: return TYPE_POINTER;
    case DW_ATE_boolean: return TYPE_INTEGER;
    case DW_ATE_float:  return bytes == 4 ? TYPE_FLOAT : TYPE_DOUBLE;
    case DW_ATE_signed:
    case DW_ATE_signed_char:
        return bytes == 1 ? TYPE_CHAR : TYPE_INTEGER;
    case DW_ATE_unsigned:
    case DW_ATE_unsigned_char:
        return bytes == 1 ? TYPE_CHAR : TYPE_UNSIGNED;
    default:
        return bytes == 8 ? TYPE_UNSIGNED : TYPE_INTEGER;
    }
}

/* DIE cursor helpers over the flat .debug_info of one CU. */

struct die_iter {
    struct dw_file *f;
    const unsigned char *p;
    const unsigned char *end;
    uint64_t cu_start;
    uint64_t abbrev_off;
};

static enum arg_type classify_type(struct dw_file *f, uint64_t die_start,
                                   uint64_t abbrev_off, uint64_t type_off,
                                   uint64_t cu_end, int depth);

#define DW_MAX_DEPTH 64

/* Sequential DIE cursor that respects the tree structure: a null abbrev
 * code closes one level of children. Returns the offset of the next DIE,
 * or UINT64_MAX on parse error. `die_off` receives the offset of the DIE
 * just read; `code_out`/`ab_out` its abbrev info (ab_out may be NULL). */
static uint64_t next_die(struct dw_file *f, const unsigned char **cur,
                         const unsigned char *end, uint64_t abbrev_off,
                         int *depth, uint64_t *die_off,
                         uint64_t *code_out, struct abbrev *ab_out)
{
    const unsigned char *p = *cur;
    *die_off = (uint64_t)(p - f->info);
    uint64_t code = rd_leb(&p, false);
    if (code == 0) {
        if (*depth > 0)
            (*depth)--;
        *cur = p;
        *code_out = 0;
        return (uint64_t)(p - f->info);
    }
    struct abbrev ab;
    if (!abbrev_at(f, abbrev_off, code, &ab))
        return UINT64_MAX;
    for (int i = 0; i < ab.nattrs; i++) {
        uint64_t u;
        if (!attr_get(f, &p, ab.attrs[i].form, ab.attrs[i].ic, &u, NULL, NULL))
            return UINT64_MAX;
    }
    if (ab.has_children)
        (*depth)++;
    if (p > end)
        return UINT64_MAX;
    if (ab_out)
        *ab_out = ab;
    *code_out = code;
    *cur = p;
    return (uint64_t)(*die_off);
}

static const unsigned char *die_at(struct dw_file *f, uint64_t die_start,
                                  uint64_t abbrev_off, uint64_t target_off,
                                  uint64_t cu_end)
{
    if (target_off >= f->info_size || target_off >= cu_end)
        return NULL;
    const unsigned char *cur = f->info + die_start;
    const unsigned char *end = f->info + cu_end;
    int depth = 0;
    while (cur < end) {
        uint64_t die_off, code;
        uint64_t r = next_die(f, &cur, end, abbrev_off, &depth, &die_off, &code, NULL);
        if (r == UINT64_MAX)
            return NULL;
        if (die_off == target_off)
            return f->info + target_off;
        if (die_off > target_off)
            return NULL;
    }
    return NULL;
}

static enum arg_type die_classify(struct dw_file *f, const unsigned char *die,
                                  uint64_t die_start, uint64_t abbrev_off,
                                  uint64_t cu_end, int depth)
{
    const unsigned char *p = die;
    uint64_t code = rd_leb(&p, false);
    struct abbrev ab;
    if (code == 0 || !abbrev_at(f, abbrev_off, code, &ab))
        return TYPE_POINTER;

    uint64_t type_ref = 0, enc = UINT64_MAX, bytes = 8;

    for (int i = 0; i < ab.nattrs; i++) {
        uint64_t u;
        const char *s;
        bool is_str;
        if (!attr_get(f, &p, ab.attrs[i].form, ab.attrs[i].ic, &u, &s, &is_str))
            break;
        if (ab.attrs[i].at == DW_AT_type)
            type_ref = u;
        else if (ab.attrs[i].at == DW_AT_encoding)
            enc = u;
        else if (ab.attrs[i].at == DW_AT_byte_size)
            bytes = u;
    }

    if (depth > 8)
        return TYPE_POINTER;

    switch (ab.tag) {
    case DW_TAG_base_type:
    case DW_TAG_enumeration_type:
        return base_to_arg(enc, bytes);
    case DW_TAG_pointer_type: {
        enum arg_type pt = type_ref
            ? classify_type(f, die_start, abbrev_off, type_ref, cu_end, depth + 1)
            : TYPE_POINTER;
        return pt == TYPE_CHAR ? TYPE_STRING : TYPE_POINTER;
    }
    case DW_TAG_typedef:
    case DW_TAG_const_type:
    case DW_TAG_volatile_type:
    case DW_TAG_restrict_type:
        return type_ref
            ? classify_type(f, die_start, abbrev_off, type_ref, cu_end, depth + 1)
            : TYPE_POINTER;
    default:
        return TYPE_POINTER;
    }
}

static enum arg_type classify_type(struct dw_file *f, uint64_t die_start,
                                   uint64_t abbrev_off, uint64_t type_off,
                                   uint64_t cu_end, int depth)
{
    const unsigned char *die = die_at(f, die_start, abbrev_off, type_off, cu_end);
    if (!die)
        return TYPE_POINTER;
    return die_classify(f, die, die_start, abbrev_off, cu_end, depth);
}

static enum ret_type arg_to_ret(enum arg_type t)
{
    switch (t) {
    case TYPE_INTEGER:  return RET_INT;
    case TYPE_UNSIGNED: return RET_UNSIGNED;
    case TYPE_POINTER:  return RET_POINTER;
    case TYPE_STRING:   return RET_STRING;
    case TYPE_DOUBLE:   return RET_DOUBLE;
    case TYPE_FLOAT:    return RET_FLOAT;
    default:            return RET_NONE;
    }
}

/* Read the .gnu_debuglink section: returns the file name (malloc'd) and
 * stores the CRC in *crc if non-NULL. */
char *dwarf_debuglink(const char *elf_path, uint32_t *crc)
{
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return NULL;
    }
    unsigned char *b = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (b == MAP_FAILED)
        return NULL;
    char *res = NULL;
    if (memcmp(b, ELFMAG, SELFMAG) == 0 && b[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)b;
        if (eh->e_shoff && eh->e_shstrndx < eh->e_shnum &&
            eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize <= (size_t)st.st_size) {
            Elf64_Shdr *shstr = (Elf64_Shdr *)(b + eh->e_shoff +
                                               (size_t)eh->e_shstrndx * eh->e_shentsize);
            if (shstr->sh_offset + shstr->sh_size <= (size_t)st.st_size) {
                for (int i = 0; i < eh->e_shnum; i++) {
                    Elf64_Shdr *sh = (Elf64_Shdr *)(b + eh->e_shoff + (size_t)i * eh->e_shentsize);
                    if (sh->sh_type == SHT_NOBITS || !sh->sh_size ||
                        sh->sh_offset + sh->sh_size > (size_t)st.st_size ||
                        sh->sh_name >= shstr->sh_size)
                        continue;
                    const char *n = (const char *)(b + shstr->sh_offset + sh->sh_name);
                    if (strcmp(n, ".gnu_debuglink") == 0) {
                        const unsigned char *dl = b + sh->sh_offset;
                        size_t len = strnlen((const char *)dl, sh->sh_size);
                        if (len > 0 && len < sh->sh_size) {
                            res = strdup((const char *)dl);
                            size_t off = (len + 1 + 3) & ~(size_t)3;
                            if (crc && off + 4 <= sh->sh_size)
                                memcpy(crc, dl + off, 4);
                        }
                        break;
                    }
                }
            }
        }
    }
    munmap(b, st.st_size);
    return res;
}

static bool walk_prototypes(const char *elf_path, const char *want_name,
                            dwarf_proto_cb cb, void *user)
{
    struct dw_file f;
    if (!dw_open(&f, elf_path)) {
        if (f.base)
            dw_close(&f);
        return false;
    }

    bool found = false;
    const unsigned char *cu = f.info;
    while (cu + 4 < f.info + f.info_size && !found) {
        const unsigned char *h = cu;
        uint64_t unit_len = rd_u(&h, 4);
        bool dwarf64 = (unit_len == 0xffffffffULL);
        if (dwarf64)
            unit_len = rd_u(&h, 8);
        if (unit_len == 0 || cu + 4 + unit_len > f.info + f.info_size)
            break;
        uint64_t cu_end = (uint64_t)(cu - f.info) + 4 + unit_len;
        if (dwarf64)
            cu_end += 4;

        uint16_t version = (uint16_t)rd_u(&h, 2);
        uint64_t abbrev_off;
        if (version >= 5) {
            h += 1; /* unit_type */
            h += 1; /* address_size */
            abbrev_off = dwarf64 ? rd_u(&h, 8) : rd_u(&h, 4);
        } else {
            /* DWARF 2/3/4: abbrev_offset then address_size */
            abbrev_off = dwarf64 ? rd_u(&h, 8) : rd_u(&h, 4);
            h += 1; /* address_size */
        }

        const unsigned char *p = f.info + cu_end;
        const unsigned char *cur = h;
        uint64_t die_start_off = (uint64_t)(h - f.info);
        uint64_t cu_end_off = cu_end;

        int depth = 0;
        while (cur < p && (!found || !want_name)) {
            struct abbrev ab;
            uint64_t code;
            {
                /* read DIE fully with attribute values */
                const unsigned char *q = cur;
                code = rd_leb(&q, false);
                if (code == 0) {
                    if (depth > 0)
                        depth--;
                    cur = q;
                    continue;
                }
                if (!abbrev_at(&f, abbrev_off, code, &ab))
                    break;
                if (ab.has_children)
                    depth++;
                cur = q;
            }

            const char *name = NULL;
            uint64_t type_ref = 0;
            bool is_subprogram = (ab.tag == DW_TAG_subprogram);
            bool has_children = ab.has_children;

            for (int i = 0; i < ab.nattrs; i++) {
                uint64_t u;
                const char *s;
                bool is_str;
                if (!attr_get(&f, &cur, ab.attrs[i].form, ab.attrs[i].ic,
                              &u, &s, &is_str))
                    break;
                if (ab.attrs[i].at == DW_AT_name && is_str)
                    name = s;
                else if (ab.attrs[i].at == DW_AT_type)
                    type_ref = u;
            }
            (void)has_children;

            if (is_subprogram && name &&
                (!want_name || strcmp(name, want_name) == 0)) {
                int na = 0;
                enum arg_type args[8];
                enum ret_type ret_here =
                    type_ref
                    ? arg_to_ret(classify_type(&f, die_start_off, abbrev_off,
                                               type_ref, cu_end_off, 0))
                    : RET_NONE;

                /* Children: formal_parameter / unspecified_parameters. */
                if (has_children) {
                    int cdepth = 1;
                    const unsigned char *c = cur;
                    while (c < p && cdepth > 0 && na < 7) {
                        uint64_t ccode;
                        struct abbrev cab;
                        const unsigned char *q = c;
                        ccode = rd_leb(&q, false);
                        if (ccode == 0) {
                            cdepth--;
                            c = q;
                            continue;
                        }
                        if (!abbrev_at(&f, abbrev_off, ccode, &cab))
                            break;
                        uint64_t cref = 0;
                        for (int i = 0; i < cab.nattrs; i++) {
                            uint64_t u;
                            const char *s;
                            bool is_str;
                            if (!attr_get(&f, &q, cab.attrs[i].form,
                                          cab.attrs[i].ic, &u, &s, &is_str))
                                break;
                            if (cab.attrs[i].at == DW_AT_type)
                                cref = u;
                        }
                        c = q;
                        if (cab.tag == DW_TAG_formal_parameter && cref) {
                            args[na++] = classify_type(&f, die_start_off,
                                                       abbrev_off, cref,
                                                       cu_end_off, 0);
                        } else if (cab.tag == DW_TAG_unspecified_parameters) {
                            break; /* variadic: stop decoding */
                        }
                        if (cab.has_children) {
                            /* skip the whole subtree of this child */
                            int sdepth = 1;
                            while (c < p && sdepth > 0) {
                                uint64_t scode = rd_leb(&c, false);
                                if (scode == 0) {
                                    sdepth--;
                                    continue;
                                }
                                struct abbrev sab;
                                if (!abbrev_at(&f, abbrev_off, scode, &sab))
                                    break;
                                uint64_t u;
                                for (int i = 0; i < sab.nattrs; i++)
                                    if (!attr_get(&f, &c, sab.attrs[i].form,
                                                  sab.attrs[i].ic, &u, NULL, NULL))
                                        break;
                                if (sab.has_children)
                                    sdepth++;
                            }
                        }
                    }
                }
                for (int i = na; i < 8; i++)
                    args[i] = TYPE_END;
                args[na < 8 ? na : 7] = TYPE_END;

                char pretty[256];
                {
                    size_t pos = 0;
                    pos += (size_t)snprintf(pretty + pos, sizeof(pretty) - pos,
                                             "%s(", name);
                    for (int i = 0; i < na && args[i] != TYPE_END; i++) {
                        const char *tn =
                            args[i] == TYPE_STRING    ? "char*" :
                            args[i] == TYPE_POINTER   ? "ptr" :
                            args[i] == TYPE_INTEGER   ? "int" :
                            args[i] == TYPE_UNSIGNED  ? "unsigned" :
                            args[i] == TYPE_DOUBLE    ? "double" :
                            args[i] == TYPE_FLOAT     ? "float" :
                            args[i] == TYPE_CHAR      ? "char" : "?";
                        pos += (size_t)snprintf(pretty + pos, sizeof(pretty) - pos,
                                                "%s%s", i ? ", " : "", tn);
                    }
                    snprintf(pretty + pos, sizeof(pretty) - pos, ")");
                }

                if (cb) {
                    found = true;
                    if (!cb(name, args, ret_here, pretty, user))
                        break;
                }
                if (want_name) {
                    found = true;
                    break;
                }
            }

        }
        cu = f.info + cu_end;
    }

    dw_close(&f);
    return found;
}

struct proto_hit {
    enum arg_type args[8];
    enum ret_type ret;
    char pretty[256];
};

static bool fill_hit_cb(const char *name, const enum arg_type args[8],
                       enum ret_type ret, const char *pretty, void *user)
{
    (void)name;
    struct proto_hit *hit = user;
    memcpy(hit->args, args, sizeof(hit->args));
    hit->ret = ret;
    memcpy(hit->pretty, pretty, sizeof(hit->pretty));
    return true; /* keep walking not needed: name mode stops anyway */
}

bool dwarf_func_prototype(const char *elf_path, const char *func_name,
                          enum arg_type args_out[8], enum ret_type *ret_out,
                          char pretty_out[256])
{
    struct proto_hit hit = { { TYPE_END }, RET_NONE, "" };

    bool ok = walk_prototypes(elf_path, func_name, fill_hit_cb, &hit);
    if (!ok)
        return false;
    if (args_out)
        memcpy(args_out, hit.args, sizeof(hit.args));
    if (ret_out)
        *ret_out = hit.ret;
    if (pretty_out)
        memcpy(pretty_out, hit.pretty, sizeof(hit.pretty));
    return true;
}

bool dwarf_list_prototypes(const char *elf_path, dwarf_proto_cb cb, void *user)
{
    return walk_prototypes(elf_path, NULL, cb, user);
}
