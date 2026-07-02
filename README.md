# WASendFix

A dylib tweak for jailbroken iOS that spoofs WhatsApp's version to bypass deprecation blocks and keep old app versions connected to WhatsApp servers.

> **Status: Working ✅**  
> Confirmed working on WhatsApp 25.1.83 / iOS 14.8 (iPhone 12 Pro Max).  
> Both startup and media sending (photos/videos) are fully functional.

---

## What This Fixes

WhatsApp periodically blocks older app versions by:
1. Checking `WABuildVersion` locally and showing an "update required" screen
2. Rejecting the connection if the app reports an old version in HTTP headers and protobuf payloads
3. Calling `abort()` internally (`WAHandleFailureInFunction`) when it detects a mismatch

Additionally, when sending media (photos/videos), WhatsApp validates enum values in protobuf messages using `GPBSetEnumIvarWithFieldPrivate`. If these values fall outside the expected range, it throws an `NSException` and crashes.

WASendFix intercepts all of these checks and returns safe spoofed values.

---

## The Spoofed Version: Why `3.99.99.99`

> **Critical:** The version string must be exactly `"3.99.99.99"`. Do not change it to a real version number.

We tested multiple values:

| Version | Result |
|---|---|
| `25.1.83` (real old build) | Server rejects it as outdated → "Update required" screen + freeze |
| `26.21.74` (real latest at time of fix) | App opens but no connection at all — server expects a newer protocol than the old binary speaks |
| `3.99.99.99` (fake non-existent) | ✅ Works — high enough to pass the "too old" check, not a real version so the server doesn't enforce a newer protocol |

The numeric components must also match: `1=3, 2=99, 3=99, 4=99`.

---

## How It Works

The dylib hooks two categories of symbols:

### 1. C Functions via GOT Rebinding (Mach-O import table patching)

Walks the `__DATA,__got` and `__DATA,__la_symbol_ptr` sections of WhatsApp and SharedModules and replaces function pointers:

| Symbol | Replacement |
|---|---|
| `WABuildVersion` | Returns `"3.99.99.99"` |
| `WABuildHTTPUserAgentString` | Returns `"WhatsApp/3.99.99.99 iOS/17.5.1 Device/iPhone_11_Pro_Max"` |
| `WAIsAfterDeprecatedPlatformCutoffDate` | Returns `0` (false — not past cutoff) |
| `WADeprecatedPlatformCutOffDate` | Returns a date 10 years in the future |
| `WABuildVersionComponent1` | Returns `3` |
| `WABuildVersionComponent2` | Returns `99` |
| `WABuildVersionComponent3` | Returns `99` |
| `WABuildVersionComponent4` | Returns `99` |
| `WAHandleFailureInFunction` | No-op (suppresses internal abort) |
| `abort` | No-op (in SharedModules' GOT — catches direct `abort()` calls) |
| `__assert_rtn` | No-op |

### 2. ObjC Method Swizzling

Uses `class_getInstanceMethod` + `method_setImplementation` to patch protobuf message classes that are sent to the server:

| Class | Method | Replacement |
|---|---|---|
| `WAPBClientPayload_UserAgent_AppVersion` | `primary` | `3` |
| `WAPBClientPayload_UserAgent_AppVersion` | `secondary` | `99` |
| `WAPBClientPayload_UserAgent_AppVersion` | `tertiary` | `99` |
| `WAPBClientPayload_UserAgent_AppVersion` | `quaternary` | `99` |
| `WAPBClientPayload_UserAgent` | `osVersion` | `"17.5.1"` |
| `WAPBClientPayload_UserAgent` | `osBuildNumber` | `"21F90"` |

---

## Bug Fixes History

### Fix 1 — Startup Freeze (✅ Fixed)

**Root cause:** A GitHub Actions auto-update workflow ran every Monday and overwrote `g_spoofedVersion` with the real App Store version (e.g. `"26.24.73"`), but left the numeric components at `3, 99, 99, 99`. This mismatch caused WhatsApp to detect an inconsistency and freeze.

**Fix:** Locked the version string to `"3.99.99.99"` in `WASendFix.c` and disabled the auto-update step in `.github/workflows/auto-update.yml`.

---

### Fix 2 — Media Send Crash / SIGABRT when sending photos or videos (✅ Fixed)

**Symptom:** App crashed with SIGABRT immediately after tapping send on a photo or video.

**Root cause (traced via Frida):**

1. `WAIsEligibleForAutoMute` builds a protobuf `WAPBMediaItemMetadata` message
2. Inside it, `GPBSetEnumIvarWithFieldPrivate` is called to set `mediaPickerOrigin`
3. The value passed in (`99` or `111`) is leaked from our version component hooks
4. `GPBSetEnumIvarWithFieldPrivate` validates enum values and throws `NSInvalidArgumentException` when the value is out of the enum's valid range:
   ```
   WAPBMediaItemMetadata.mediaPickerOrigin: Attempt to set an unknown enum value (99)
   ```
5. The uncaught ObjC exception propagates → `abort()` → SIGABRT

**Fix (in the Frida script `wasendfix_v2.js`, to be ported to dylib):**
- Hook `WAIsEligibleForAutoMute` → return `0` directly (skip the protobuf construction entirely)
- Hook `GPBSetEnumIvarWithFieldPrivate` → clamp any enum value `> 10` to `0` before GPB validates it
- Hook `abort()` from `libsystem_c.dylib` globally (not just via GOT in SharedModules)
- Bypass SSL certificate pinning via `SecTrustEvaluate` / `SecTrustEvaluateWithError`
- Return `nil` from `MBIGetCertificatePinningFromBundles` (disables the pinning config)

---

## Files

| File | Description |
|---|---|
| `WASendFix.c` | Main dylib source — injected into WhatsApp at runtime |
| `build.sh` | Build script (cross-compiles for arm64 iOS) |
| `headers/` | Minimal iOS headers (no Xcode required) |
| `stubs/` | Stub libraries for linking |
| `.github/workflows/build.yml` | CI — builds the dylib on every push to `main` |
| `.github/workflows/auto-update.yml` | Auto-update (disabled — must not overwrite version string) |

---

## Frida Development Script (`wasendfix_v2.js`)

For testing and diagnosing new crashes without rebuilding the dylib. Requires Frida 16+ on the host and `frida-server` on the device.

**Frida 17 note:** `Module.findExportByName()` was removed. Use `Process.findModuleByName(mod).findExportByName(sym)` instead.

```bash
frida -U -f net.whatsapp.WhatsApp -l wasendfix_v2.js
```

Expected output on success:
```
[abort] patched -> thread-sleep
[SecTrustEvaluate] bypassed
[SecTrustEvaluateWithError] bypassed
[SharedModules] symbols found: 12
[GPBSetEnumIvarWithFieldPrivate] clamp hook installed
[WABuildVersionComponent1-4] patched -> 3.99.99.99
[WABuildVersion] patched -> 3.99.99.99
[MBIGetCertPinning] patched -> nil
[WAIsEligibleForAutoMute] patched -> 0
[wasendfix v2] ALL READY
```

If a media send was previously crashing you will now see:
```
[GPBSetEnum] clamped 99 -> 0
```

---

## Installation

1. Download `WASendFix.dylib` from **Actions → latest build → Artifacts → WASendFix-dylib**
2. Use **TrollFools** or **TrollStore** to inject it into WhatsApp (placed in `Frameworks/`)
3. Open WhatsApp — it connects normally

No Cydia Substrate or libhooker required. Works on any iOS 14+ device with TrollStore or a jailbreak.

---

## Known Limitations

- Only tested on WhatsApp 25.1.83. Newer versions may add additional version checks.
- The dylib currently only patches GOT imports, not direct internal branches. `WAHandleFailureInFunction` is suppressed via its `abort()` GOT entry, not by patching the function itself.
- The GPB enum clamp fix is currently only in `wasendfix_v2.js` (Frida script) and has not yet been ported to `WASendFix.c`.

---

## Technical Notes

- No `MSHookFunction` or CydiaSubstrate dependency
- Uses `CFStringCreateWithCString` / `CFDateCreate` directly (avoids `objc_msgSend` variadic casting issues in cross-compilation)
- Spoofed strings are retained in memory for the lifetime of the process
- The 10-year future date means the deprecation cutoff bypass will not expire before 2034
