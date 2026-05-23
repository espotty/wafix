#include <stdint.h>
#include "headers/objc/runtime.h"
#include "headers/mach-o/dyld.h"
#include "headers/mach-o/loader.h"

#define NULL ((void*)0)

extern void *CFStringCreateWithCString(void *alloc, const char *cStr, uint32_t encoding);
extern void *CFDateCreate(void *alloc, double at);
extern double CFAbsoluteTimeGetCurrent(void);
extern void *CFRetain(void *cf);

#define kCFStringEncodingUTF8 0x08000100


__attribute__((section("__DATA,__objc_imageinfo"), used))
static const uint32_t _objc_imageinfo[2] = { 0, 0 };

static id g_spoofedVersion   = NULL;
static id g_spoofedUA        = NULL;
static id g_spoofedOsVersion = NULL;
static id g_spoofedOsBuild   = NULL;
static id g_futureDate       = NULL;

static void create_objc_objects(void) {
    g_spoofedVersion = (id)CFStringCreateWithCString(NULL, "3.99.99.99", kCFStringEncodingUTF8);
    g_spoofedUA      = (id)CFStringCreateWithCString(NULL,
                        "WhatsApp/3.99.99.99 iOS/17.5.1 Device/iPhone_11_Pro_Max",
                        kCFStringEncodingUTF8);
    g_spoofedOsVersion = (id)CFStringCreateWithCString(NULL, "17.5.1", kCFStringEncodingUTF8);
    g_spoofedOsBuild   = (id)CFStringCreateWithCString(NULL, "21F90", kCFStringEncodingUTF8);

    double future = CFAbsoluteTimeGetCurrent() + 315360000.0;
    g_futureDate = (id)CFDateCreate(NULL, future);
}

static id fake_WABuildVersion(void)                        { return g_spoofedVersion; }
static id fake_WABuildHTTPUserAgentString(void)             { return g_spoofedUA; }
static int fake_WAIsAfterDeprecatedPlatformCutoffDate(void) { return 0; }
static id fake_WADeprecatedPlatformCutOffDate(void)         { return g_futureDate; }
static int fake_WABuildVersionComponent1(void)              { return 3; }
static int fake_WABuildVersionComponent2(void)              { return 99; }
static int fake_WABuildVersionComponent3(void)              { return 99; }
static int fake_WABuildVersionComponent4(void)              { return 99; }
static void fake_WAHandleFailureInFunction(void)            { return; }

static unsigned int pb_ret3(id self, SEL cmd)  { (void)self;(void)cmd; return 3;  }
static unsigned int pb_ret99(id self, SEL cmd) { (void)self;(void)cmd; return 99; }

static id fake_osVersion_getter(id self, SEL cmd) {
    (void)self; (void)cmd;
    return g_spoofedOsVersion;
}

static id fake_osBuildNumber_getter(id self, SEL cmd) {
    (void)self; (void)cmd;
    return g_spoofedOsBuild;
}

static int name_match(const char *sym, const char *target) {
    if (!sym || !target) return 0;
    while (*target) {
        if (*sym != *target) return 0;
        sym++; target++;
    }
    return *sym == '\0';
}

static int str_contains(const char *s, const char *sub) {
    if (!s || !sub) return 0;
    for (; *s; s++) {
        const char *a = s, *b = sub;
        while (*b && *a == *b) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}

struct hook_entry {
    const char *name;
    void *replacement;
};

static struct hook_entry g_hooks[] = {
    { "_WAHandleFailureInFunction",            (void*)fake_WAHandleFailureInFunction },
    { "_WAIsAfterDeprecatedPlatformCutoffDate", (void*)fake_WAIsAfterDeprecatedPlatformCutoffDate },
    { "_WADeprecatedPlatformCutOffDate",        (void*)fake_WADeprecatedPlatformCutOffDate },
    { "_WABuildVersion",                        (void*)fake_WABuildVersion },
    { "_WABuildHTTPUserAgentString",            (void*)fake_WABuildHTTPUserAgentString },
    { "_WABuildVersionComponent1",              (void*)fake_WABuildVersionComponent1 },
    { "_WABuildVersionComponent2",              (void*)fake_WABuildVersionComponent2 },
    { "_WABuildVersionComponent3",              (void*)fake_WABuildVersionComponent3 },
    { "_WABuildVersionComponent4",              (void*)fake_WABuildVersionComponent4 },
};
#define N_HOOKS 9

static void rebind_imports_in_image(const struct mach_header_64 *header, intptr_t slide) {
    if (!header || header->magic != MH_MAGIC_64) return;
    if (header->ncmds == 0 || header->ncmds > 4096) return;

    const struct load_command *lc =
        (const struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));

    const struct symtab_command   *symtab_cmd   = NULL;
    const struct dysymtab_command *dysymtab_cmd  = NULL;
    uint64_t linkedit_vmaddr = 0, linkedit_fileoff = 0, text_vmaddr = 0;
    int found_le = 0, found_tx = 0;

    struct { uint64_t addr; uint64_t size; uint32_t reserved1; } sects[64];
    int n_sects = 0;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (!lc || lc->cmdsize < 8) return;

        if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            symtab_cmd = (const struct symtab_command *)lc;
        }
        else if (lc->cmd == LC_DYSYMTAB && lc->cmdsize >= sizeof(struct dysymtab_command)) {
            dysymtab_cmd = (const struct dysymtab_command *)lc;
        }
        else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (seg->segname[0] != '_' || seg->segname[1] != '_') goto next;

            if (seg->segname[2]=='L' && seg->segname[3]=='I' &&
                seg->segname[4]=='N' && seg->segname[5]=='K' && seg->segname[6]=='E') {
                linkedit_vmaddr  = seg->vmaddr;
                linkedit_fileoff = seg->fileoff;
                found_le = 1;
            }
            else if (seg->segname[2]=='T' && seg->segname[3]=='E' &&
                     seg->segname[4]=='X' && seg->segname[5]=='T' && seg->segname[6]=='\0') {
                text_vmaddr = seg->vmaddr;
                found_tx = 1;
            }
            else if (seg->segname[2]=='D' && seg->segname[3]=='A' &&
                     seg->segname[4]=='T' && seg->segname[5]=='A') {
                if (seg->nsects > 256) goto next;
                const struct section_64 *sec =
                    (const struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects && n_sects < 64; j++) {
                    uint32_t type = sec[j].flags & SECTION_TYPE;
                    if (type == S_NON_LAZY_SYMBOL_POINTERS || type == S_LAZY_SYMBOL_POINTERS) {
                        sects[n_sects].addr      = sec[j].addr;
                        sects[n_sects].size      = sec[j].size;
                        sects[n_sects].reserved1 = sec[j].reserved1;
                        n_sects++;
                    }
                }
            }
        }
next:
        lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    if (!symtab_cmd || !dysymtab_cmd || !found_le || !found_tx) return;
    if (symtab_cmd->nsyms == 0 || symtab_cmd->strsize == 0) return;
    if (dysymtab_cmd->nindirectsyms == 0 || n_sects == 0) return;
    if (linkedit_vmaddr < text_vmaddr) return;
    if (symtab_cmd->symoff < linkedit_fileoff) return;
    if (symtab_cmd->stroff < linkedit_fileoff) return;
    if (dysymtab_cmd->indirectsymoff < linkedit_fileoff) return;

    uintptr_t le_base = (uintptr_t)header + (linkedit_vmaddr - text_vmaddr);
    const struct nlist_64 *nlist   = (const struct nlist_64 *)(le_base + (symtab_cmd->symoff - linkedit_fileoff));
    const char           *strtab  = (const char *)(le_base + (symtab_cmd->stroff - linkedit_fileoff));
    const uint32_t       *indsyms = (const uint32_t *)(le_base + (dysymtab_cmd->indirectsymoff - linkedit_fileoff));

    uint32_t nsyms   = symtab_cmd->nsyms;
    uint32_t strsize = symtab_cmd->strsize;
    uint32_t ninds   = dysymtab_cmd->nindirectsyms;

    for (int s = 0; s < n_sects; s++) {
        if (sects[s].size == 0) continue;
        uint32_t n_entries = (uint32_t)(sects[s].size / sizeof(void*));
        void **ptrs = (void **)((uintptr_t)sects[s].addr + (uintptr_t)slide);
        uint32_t base = sects[s].reserved1;

        for (uint32_t e = 0; e < n_entries; e++) {
            uint32_t pos = base + e;
            if (pos >= ninds) break;

            uint32_t sym_idx = indsyms[pos];
            if (sym_idx & (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
            if (sym_idx >= nsyms) continue;

            uint32_t strx = nlist[sym_idx].n_un.n_strx;
            if (strx == 0 || strx >= strsize) continue;

            const char *sn = strtab + strx;
            if (sn[0] != '_' || sn[1] != 'W' || sn[2] != 'A') continue;

            for (int h = 0; h < N_HOOKS; h++) {
                if (name_match(sn, g_hooks[h].name)) {
                    ptrs[e] = g_hooks[h].replacement;
                    break;
                }
            }
        }
    }
}

static void hook_c_functions(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (!str_contains(name, "SharedModules") &&
            !str_contains(name, "WhatsApp.app/WhatsApp"))
            continue;

        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        rebind_imports_in_image(hdr, slide);
    }
}

static void hook_objc_classes(void) {
    Class cls = (Class)objc_getClass("WAPBClientPayload_UserAgent_AppVersion");
    if (cls) {
        struct { const char *n; IMP fn; } h[] = {
            { "primary",    (IMP)pb_ret3  },
            { "secondary",  (IMP)pb_ret99 },
            { "tertiary",   (IMP)pb_ret99 },
            { "quaternary", (IMP)pb_ret99 },
        };
        for (int i = 0; i < 4; i++) {
            Method m = class_getInstanceMethod(cls, sel_registerName(h[i].n));
            if (m) method_setImplementation(m, h[i].fn);
        }
    }

    Class uaCls = (Class)objc_getClass("WAPBClientPayload_UserAgent");
    if (uaCls) {
        Method m1 = class_getInstanceMethod(uaCls, sel_registerName("osVersion"));
        if (m1) method_setImplementation(m1, (IMP)fake_osVersion_getter);
        Method m2 = class_getInstanceMethod(uaCls, sel_registerName("osBuildNumber"));
        if (m2) method_setImplementation(m2, (IMP)fake_osBuildNumber_getter);
    }
}

__attribute__((constructor))
static void tweak_init(void) {
    create_objc_objects();
    hook_c_functions();
    hook_objc_classes();
}
