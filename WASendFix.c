#include <stdint.h>
#include "headers/objc/runtime.h"
#include "headers/mach-o/dyld.h"
#include "headers/mach-o/loader.h"

#define NULL ((void*)0)

/* ── CoreFoundation (no ObjC messaging needed for string/date creation) ──── */
extern void *CFStringCreateWithCString(void *alloc, const char *cStr, uint32_t encoding);
extern void *CFDateCreate(void *alloc, double at);
extern double CFAbsoluteTimeGetCurrent(void);
extern void *CFRetain(void *cf);
#define kCFStringEncodingUTF8 0x08000100

/* ── Memory protection (for ARM64 body patching) ────────────────────────── */
extern int mprotect(void *addr, uint64_t len, int prot);
extern void sys_icache_invalidate(void *start, uint64_t length);
#define PROT_READ  0x01
#define PROT_WRITE 0x02
#define PROT_EXEC  0x04
#define IOS_PAGE_SIZE 0x4000  /* 16 KB on Apple Silicon */

/* ── Required for Security framework bypass ─────────────────────────────── */
/* SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) → OSStatus */
/* SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error)  → Boolean  */
/* We declare them here so the compiler knows their types; no stub needed     */
/* because we only put pointers in the GOT — we never call them from dylib.  */

__attribute__((section("__DATA,__objc_imageinfo"), used))
static const uint32_t _objc_imageinfo[2] = { 0, 0 };

/* ── Spoofed ObjC objects (created once at init) ────────────────────────── */
static id g_spoofedVersion   = NULL;
static id g_spoofedUA        = NULL;
static id g_spoofedOsVersion = NULL;
static id g_spoofedOsBuild   = NULL;
static id g_futureDate       = NULL;

static void create_objc_objects(void) {
    g_spoofedVersion = (id)CFStringCreateWithCString(NULL, "3.99.99.99",
                                                     kCFStringEncodingUTF8);
    g_spoofedUA      = (id)CFStringCreateWithCString(NULL,
                        "WhatsApp/3.99.99.99 iOS/17.5.1 Device/iPhone_11_Pro_Max",
                        kCFStringEncodingUTF8);
    g_spoofedOsVersion = (id)CFStringCreateWithCString(NULL, "17.5.1",
                                                       kCFStringEncodingUTF8);
    g_spoofedOsBuild   = (id)CFStringCreateWithCString(NULL, "21F90",
                                                       kCFStringEncodingUTF8);
    double future = CFAbsoluteTimeGetCurrent() + 315360000.0; /* ~10 years */
    g_futureDate = (id)CFDateCreate(NULL, future);
}

/* ── Replacement functions ──────────────────────────────────────────────── */

/* Version spoof */
static id fake_WABuildVersion(void)                        { return g_spoofedVersion; }
static id fake_WABuildHTTPUserAgentString(void)             { return g_spoofedUA; }
static int fake_WAIsAfterDeprecatedPlatformCutoffDate(void) { return 0; }
static id fake_WADeprecatedPlatformCutOffDate(void)         { return g_futureDate; }
static int fake_WABuildVersionComponent1(void)              { return 3; }
static int fake_WABuildVersionComponent2(void)              { return 99; }
static int fake_WABuildVersionComponent3(void)              { return 99; }
static int fake_WABuildVersionComponent4(void)              { return 99; }
static void fake_WAHandleFailureInFunction(void)            { return; }

/* Suppress abort() and assertions in SharedModules' GOT */
static void fake_abort(void)       { return; }
static void fake_assert_rtn(void)  { return; }

/*
 * Media send crash fix — GOT portion
 *
 * WAIsEligibleForAutoMute / WAIsEligibleForAutoDownload:
 *   These build a WAPBMediaItemMetadata protobuf message and call
 *   GPBSetEnumIvarWithFieldPrivate(self, field, value=99).  GPB
 *   validates the enum and throws NSInvalidArgumentException when
 *   value=99 is not in the enum's valid set → SIGABRT crash.
 *   Returning 0 (not eligible) avoids the crash entirely.
 *
 * MBIGetCertificatePinningFromBundles:
 *   Returns nil to disable certificate-pinning config for media uploads.
 *
 * SecTrustEvaluate / SecTrustEvaluateWithError:
 *   Patched in WhatsApp's GOT so all TLS cert evaluations succeed,
 *   allowing media uploads on old iOS / WA versions without valid certs.
 */
static int  fake_WAIsEligibleForAutoMute(void)      { return 0; }
static int  fake_WAIsEligibleForAutoDownload(void)  { return 0; }
static void *fake_MBIGetCertificatePinningFromBundles(void *arg) { (void)arg; return NULL; }

/* SecTrustEvaluate(trust, *result) → 0 = errSecSuccess */
static int fake_SecTrustEvaluate(void *trust, int *result) {
    (void)trust;
    if (result) *result = 1; /* kSecTrustResultProceed */
    return 0;                /* errSecSuccess */
}

/* SecTrustEvaluateWithError(trust, *error) → 1 = trusted */
static int fake_SecTrustEvaluateWithError(void *trust, void **error) {
    (void)trust;
    if (error) *error = NULL;
    return 1; /* true */
}

/* ── ObjC protobuf swizzle stubs ───────────────────────────────────────── */
static unsigned int pb_ret3(id self, SEL cmd)  { (void)self; (void)cmd; return 3;  }
static unsigned int pb_ret99(id self, SEL cmd) { (void)self; (void)cmd; return 99; }

static id fake_osVersion_getter(id self, SEL cmd) {
    (void)self; (void)cmd; return g_spoofedOsVersion;
}
static id fake_osBuildNumber_getter(id self, SEL cmd) {
    (void)self; (void)cmd; return g_spoofedOsBuild;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
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

/*
 * patch_to_ret0 — ARM64 body patch: overwrite the first 8 bytes of any
 * function with:
 *   MOV X0, #0   (0xD2800000)
 *   RET          (0xD65F03C0)
 *
 * Used for WAIsEligibleForAutoMute / WAIsEligibleForAutoDownload because:
 *   • GOT patching only intercepts calls that go through the import table
 *     (cross-binary calls).  Internal direct-branch calls within SharedModules
 *     bypass the GOT and would still crash.
 *   • A body patch intercepts ALL callers regardless of call site.
 *   • No trampoline needed because we don't call the original — returning 0
 *     (not eligible) is a safe no-op for these eligibility predicates.
 */
static void patch_to_ret0(void *addr) {
    if (!addr) return;
    uintptr_t a    = (uintptr_t)addr;
    uintptr_t page = a & ~(uintptr_t)(IOS_PAGE_SIZE - 1);
    mprotect((void *)page, IOS_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
    volatile uint32_t *p = (volatile uint32_t *)addr;
    p[0] = 0xD2800000; /* MOV X0, #0 */
    p[1] = 0xD65F03C0; /* RET        */
    sys_icache_invalidate(addr, 8);
    mprotect((void *)page, IOS_PAGE_SIZE, PROT_READ | PROT_EXEC);
}

/* ── GOT hook table ──────────────────────────────────────────────────────── */
struct hook_entry {
    const char *name;
    void *replacement;
};

static struct hook_entry g_hooks[] = {
    /* Version spoof */
    { "_WAHandleFailureInFunction",             (void*)fake_WAHandleFailureInFunction },
    { "_WAIsAfterDeprecatedPlatformCutoffDate", (void*)fake_WAIsAfterDeprecatedPlatformCutoffDate },
    { "_WADeprecatedPlatformCutOffDate",        (void*)fake_WADeprecatedPlatformCutOffDate },
    { "_WABuildVersion",                        (void*)fake_WABuildVersion },
    { "_WABuildHTTPUserAgentString",            (void*)fake_WABuildHTTPUserAgentString },
    { "_WABuildVersionComponent1",              (void*)fake_WABuildVersionComponent1 },
    { "_WABuildVersionComponent2",              (void*)fake_WABuildVersionComponent2 },
    { "_WABuildVersionComponent3",              (void*)fake_WABuildVersionComponent3 },
    { "_WABuildVersionComponent4",              (void*)fake_WABuildVersionComponent4 },
    /* Suppress crash helpers in SharedModules' GOT */
    { "_abort",                                 (void*)fake_abort },
    { "___assert_rtn",                          (void*)fake_assert_rtn },
    /* Media send crash fix — GOT layer (cross-binary callers) */
    { "_WAIsEligibleForAutoMute",               (void*)fake_WAIsEligibleForAutoMute },
    { "_WAIsEligibleForAutoDownload",           (void*)fake_WAIsEligibleForAutoDownload },
    { "_MBIGetCertificatePinningFromBundles",   (void*)fake_MBIGetCertificatePinningFromBundles },
    /* SSL certificate pinning bypass */
    { "_SecTrustEvaluate",                      (void*)fake_SecTrustEvaluate },
    { "_SecTrustEvaluateWithError",             (void*)fake_SecTrustEvaluateWithError },
};
#define N_HOOKS (sizeof(g_hooks) / sizeof(g_hooks[0]))

/* ── Body-patch targets (functions that need prologue patching, not GOT) ─── */
struct patch_entry {
    const char *name;   /* bare symbol name without leading underscore */
    void *found_addr;   /* filled in during symbol scan */
};

static struct patch_entry g_patches[] = {
    /*
     * WAIsEligibleForAutoMute: called internally within SharedModules via
     * direct branch — GOT hook alone doesn't catch it.  Body-patch ensures
     * ALL callers (internal + external) see return 0.
     */
    { "WAIsEligibleForAutoMute",  NULL },
    { "WAIsEligibleForAutoDownload", NULL },
};
#define N_PATCHES (sizeof(g_patches) / sizeof(g_patches[0]))

/* ── Mach-O GOT rebinding ────────────────────────────────────────────────── */
static void rebind_and_scan_image(const struct mach_header_64 *header, intptr_t slide) {
    if (!header || header->magic != MH_MAGIC_64) return;
    if (header->ncmds == 0 || header->ncmds > 4096) return;

    const struct load_command *lc =
        (const struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));

    const struct symtab_command   *symtab_cmd   = NULL;
    const struct dysymtab_command *dysymtab_cmd = NULL;
    uint64_t linkedit_vmaddr = 0, linkedit_fileoff = 0, text_vmaddr = 0;
    int found_le = 0, found_tx = 0;

    struct { uint64_t addr; uint64_t size; uint32_t reserved1; } sects[64];
    int n_sects = 0;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (!lc || lc->cmdsize < 8) return;

        if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            symtab_cmd = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_DYSYMTAB && lc->cmdsize >= sizeof(struct dysymtab_command)) {
            dysymtab_cmd = (const struct dysymtab_command *)lc;
        } else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (seg->segname[0] != '_' || seg->segname[1] != '_') goto next;

            if (seg->segname[2]=='L' && seg->segname[3]=='I' &&
                seg->segname[4]=='N' && seg->segname[5]=='K' && seg->segname[6]=='E') {
                linkedit_vmaddr  = seg->vmaddr;
                linkedit_fileoff = seg->fileoff;
                found_le = 1;
            } else if (seg->segname[2]=='T' && seg->segname[3]=='E' &&
                       seg->segname[4]=='X' && seg->segname[5]=='T' && seg->segname[6]=='\0') {
                text_vmaddr = seg->vmaddr;
                found_tx = 1;
            } else if (seg->segname[2]=='D' && seg->segname[3]=='A' &&
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

    /* ---- GOT patch via indirect symbol table ----------------------------- */
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
            if (sn[0] != '_') continue;

            for (int h = 0; h < (int)N_HOOKS; h++) {
                if (name_match(sn, g_hooks[h].name)) {
                    ptrs[e] = g_hooks[h].replacement;
                    break;
                }
            }
        }
    }

    /* ---- Body-patch target discovery via full symbol table --------------- */
    /* Walk every exported symbol to find addresses for body patching.        */
    for (uint32_t si = 0; si < nsyms; si++) {
        uint32_t strx = nlist[si].n_un.n_strx;
        if (strx == 0 || strx >= strsize) continue;
        /* Only defined symbols in __TEXT */
        if ((nlist[si].n_type & 0x0e) != 0x0e) continue; /* N_SECT */
        if (nlist[si].n_value == 0) continue;

        const char *sn = strtab + strx;
        /* Skip leading underscore for comparison */
        const char *bare = (sn[0] == '_') ? sn + 1 : sn;

        for (int p = 0; p < (int)N_PATCHES; p++) {
            if (!g_patches[p].found_addr && name_match(bare, g_patches[p].name)) {
                g_patches[p].found_addr = (void *)(nlist[si].n_value + (uint64_t)slide);
            }
        }
    }
}

/* ── Main hook entry point ───────────────────────────────────────────────── */
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
        rebind_and_scan_image(hdr, slide);
    }

    /* Apply body patches after all images are scanned */
    for (int p = 0; p < (int)N_PATCHES; p++) {
        if (g_patches[p].found_addr) {
            patch_to_ret0(g_patches[p].found_addr);
        }
    }
}

/* ── ObjC method swizzling ───────────────────────────────────────────────── */
static void hook_objc_classes(void) {
    /* WAPBClientPayload_UserAgent_AppVersion: primary=3, secondary/tertiary/quaternary=99 */
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

    /* WAPBClientPayload_UserAgent: osVersion, osBuildNumber */
    Class uaCls = (Class)objc_getClass("WAPBClientPayload_UserAgent");
    if (uaCls) {
        Method m1 = class_getInstanceMethod(uaCls, sel_registerName("osVersion"));
        if (m1) method_setImplementation(m1, (IMP)fake_osVersion_getter);
        Method m2 = class_getInstanceMethod(uaCls, sel_registerName("osBuildNumber"));
        if (m2) method_setImplementation(m2, (IMP)fake_osBuildNumber_getter);
    }
}

/* ── Constructor ─────────────────────────────────────────────────────────── */
__attribute__((constructor))
static void tweak_init(void) {
    create_objc_objects();
    hook_c_functions();
    hook_objc_classes();
}
