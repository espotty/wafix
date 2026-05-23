#pragma once
#include <stdint.h>
#include "dyld.h"

#define MH_MAGIC_64     0xfeedfacf
#define MH_EXECUTE      0x2
#define MH_DYLIB        0x6
#define LC_SYMTAB       0x2
#define LC_SEGMENT_64   0x19
#define LC_DYSYMTAB     0xb
#define N_EXT           0x01
#define N_TYPE          0x0e
#define N_SECT          0xe

#define S_NON_LAZY_SYMBOL_POINTERS  0x6
#define S_LAZY_SYMBOL_POINTERS      0x7
#define SECTION_TYPE                0x000000ff

#define INDIRECT_SYMBOL_ABS   0x40000000
#define INDIRECT_SYMBOL_LOCAL 0x80000000

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t  cmd;
    uint32_t  cmdsize;
    char      segname[16];
    uint64_t  vmaddr;
    uint64_t  vmsize;
    uint64_t  fileoff;
    uint64_t  filesize;
    int       maxprot;
    int       initprot;
    uint32_t  nsects;
    uint32_t  flags;
};

struct symtab_command {
    uint32_t  cmd;
    uint32_t  cmdsize;
    uint32_t  symoff;
    uint32_t  nsyms;
    uint32_t  stroff;
    uint32_t  strsize;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

struct section_64 {
    char      sectname[16];
    char      segname[16];
    uint64_t  addr;
    uint64_t  size;
    uint32_t  offset;
    uint32_t  align;
    uint32_t  reloff;
    uint32_t  nreloc;
    uint32_t  flags;
    uint32_t  reserved1;
    uint32_t  reserved2;
    uint32_t  reserved3;
};

struct nlist_64 {
    union {
        uint32_t  n_strx;
    } n_un;
    uint8_t   n_type;
    uint8_t   n_sect;
    uint16_t  n_desc;
    uint64_t  n_value;
};
