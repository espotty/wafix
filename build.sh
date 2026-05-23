#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

TARGET="arm64-apple-ios14.0"
OUT="output/WASendFix.dylib"
STUBS="$(pwd)/stubs"

echo "[*] Compiling WASendFix.c → arm64 Mach-O object..."

clang \
    -target "$TARGET" \
    -arch arm64 \
    -I ./headers \
    -nostdinc \
    -fno-stack-protector \
    -fvisibility=hidden \
    -O2 \
    -Wno-incompatible-library-redeclaration \
    -c WASendFix.c \
    -o output/WASendFix.o

echo "[*] Linking Mach-O dylib → $OUT ..."
ld64.lld \
    -arch arm64 \
    -platform_version ios 14.0.0 14.0.0 \
    -dylib \
    -install_name "@rpath/WASendFix.dylib" \
    -no_fixup_chains \
    -no_data_const \
    "$STUBS/usr/lib/libobjc.A.tbd" \
    "$STUBS/usr/lib/libSystem.B.tbd" \
    "$STUBS/System/Library/Frameworks/Foundation.framework/Foundation.tbd" \
    "$STUBS/System/Library/Frameworks/UIKit.framework/UIKit.tbd" \
    "$STUBS/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd" \
    output/WASendFix.o \
    -o "$OUT"

echo "[+] Build successful!"
file "$OUT"
ls -lh "$OUT"

echo ""
echo "[*] Verifying Mach-O format..."
python3 - "$OUT" <<'PYCHECK'
import struct, sys

with open(sys.argv[1], 'rb') as f:
    b = f.read()

ncmds = struct.unpack_from('<I', b, 0x10)[0]
off = 0x20
has_old = has_new = False
n_dylibs = 0; n_ind = 0
for i in range(ncmds):
    cmd, sz = struct.unpack_from('<II', b, off)
    if cmd == 0x80000022: has_old = True
    if cmd == 0x80000034: has_new = True
    if cmd == 0x0C: n_dylibs += 1
    if cmd == 0x0B: n_ind = struct.unpack_from('<I', b, off+76)[0]
    off += sz

ok = True
if has_new:
    print("[!] FAIL: Uses LC_DYLD_CHAINED_FIXUPS — will crash on iOS 14!"); ok = False
elif has_old:
    print("[✓] Uses LC_DYLD_INFO_ONLY — iOS 14 compatible")
else:
    print("[!] FAIL: No binding format!"); ok = False

if n_dylibs > 0:
    print(f"[✓] Links {n_dylibs} system libraries")
else:
    print("[!] WARN: No LC_LOAD_DYLIB entries"); ok = False

if n_ind > 0:
    print(f"[✓] Indirect symbol table: {n_ind} entries")
else:
    print("[!] WARN: No indirect symbol entries")

if ok: print("\n[✓] Dylib should load on iOS 14.8")
sys.exit(0 if ok else 1)
PYCHECK
