#ifndef FORENSICS_DWARF_CONSTS_H
#define FORENSICS_DWARF_CONSTS_H

/* Minimal DWARF constants (not provided by older elf.h). */

#define DW_TAG_array_type             0x01
#define DW_TAG_enumeration_type       0x04
#define DW_TAG_formal_parameter       0x05
#define DW_TAG_subprogram             0x2e
#define DW_TAG_structure_type         0x13
#define DW_TAG_base_type              0x24
#define DW_TAG_pointer_type           0x0f
#define DW_TAG_compile_unit            0x11
#define DW_TAG_const_type             0x26
#define DW_TAG_subroutine_type        0x15
#define DW_TAG_typedef                0x16
#define DW_TAG_union_type             0x17
#define DW_TAG_unspecified_parameters 0x18
#define DW_TAG_variant                0x19
#define DW_TAG_class_type             0x02
#define DW_TAG_volatile_type          0x35
#define DW_TAG_restrict_type          0x37

#define DW_AT_location   0x02
#define DW_AT_name       0x03
#define DW_AT_byte_size  0x0b
#define DW_AT_stmt_list  0x10
#define DW_AT_low_pc     0x11
#define DW_AT_high_pc    0x12
#define DW_AT_language   0x13
#define DW_AT_comp_dir   0x1b
#define DW_AT_prototyped 0x27
#define DW_AT_type       0x49
#define DW_AT_encoding   0x3e

#define DW_FORM_addr         0x01
#define DW_FORM_block2       0x03
#define DW_FORM_block4       0x04
#define DW_FORM_data2         0x05
#define DW_FORM_data4         0x06
#define DW_FORM_data8         0x07
#define DW_FORM_string        0x08
#define DW_FORM_block         0x09
#define DW_FORM_block1        0x0a
#define DW_FORM_data1         0x0b
#define DW_FORM_flag          0x0c
#define DW_FORM_sdata         0x0d
#define DW_FORM_strp          0x0e
#define DW_FORM_udata         0x0f
#define DW_FORM_ref_addr      0x10
#define DW_FORM_ref1          0x11
#define DW_FORM_ref2          0x12
#define DW_FORM_ref4          0x13
#define DW_FORM_ref8          0x14
#define DW_FORM_ref_udata     0x15
#define DW_FORM_indirect      0x16
#define DW_FORM_sec_offset    0x17
#define DW_FORM_exprloc       0x18
#define DW_FORM_flag_present  0x19
#define DW_FORM_ref_sig8      0x20
#define DW_FORM_strx          0x1a
#define DW_FORM_addrx         0x1b
#define DW_FORM_ref_sup4      0x1c
#define DW_FORM_strp_sup      0x1d
#define DW_FORM_data16        0x1e
#define DW_FORM_line_strp     0x1f
#define DW_FORM_ref_sig      0x20
#define DW_FORM_implicit_const 0x21
#define DW_FORM_loclistx      0x22
#define DW_FORM_rnglistx      0x23
#define DW_FORM_ref_sup8      0x24
#define DW_FORM_strx1         0x25
#define DW_FORM_strx2         0x26
#define DW_FORM_strx3         0x27
#define DW_FORM_strx4         0x28
#define DW_FORM_addrx1        0x29

#define DW_ATE_address     0x01
#define DW_ATE_boolean     0x02
#define DW_ATE_float       0x04
#define DW_ATE_signed      0x05
#define DW_ATE_signed_char 0x06
#define DW_ATE_unsigned    0x07
#define DW_ATE_unsigned_char 0x08

#endif
