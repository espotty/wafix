#pragma once
#include <stdint.h>

struct mach_header {
    uint32_t magic;
    int      cputype;
    int      cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct mach_header_64 {
    uint32_t magic;
    int      cputype;
    int      cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

extern uint32_t    _dyld_image_count(void);
extern const struct mach_header* _dyld_get_image_header(uint32_t image_index);
extern intptr_t    _dyld_get_image_vmaddr_slide(uint32_t image_index);
extern const char* _dyld_get_image_name(uint32_t image_index);
extern void        _dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
