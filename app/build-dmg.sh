#!/usr/bin/env bash
# Build Localite.app and Localite.dmg on an Apple Silicon Mac with Xcode Command Line Tools,
# Rust, the aarch64-unknown-linux-musl Rust target, and Zig.
set -euo pipefail
cd "$(dirname "$0")"
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || { echo "Run on an Apple Silicon Mac."; exit 1; }

echo "==> Building isolated guest and pinned Moto API backend"
ZIG="${ZIG:?Set ZIG to the Zig executable path for macOS cross-builds}" bash ../guest/build-initrd.sh

KATA_VER=3.20.0
KERNEL_IN_TAR=./opt/kata/share/kata-containers/vmlinux-6.12.42-162
CACHE=.cache; mkdir -p "$CACHE"
if [ ! -f "$CACHE/vmlinux" ]; then
  echo "==> Downloading guest kernel (Kata Containers $KATA_VER arm64 bundle, ~295 MB, one time)…"
  curl -L --fail -o "$CACHE/kata.tar.xz" \
    "https://github.com/kata-containers/kata-containers/releases/download/$KATA_VER/kata-static-$KATA_VER-arm64.tar.xz"
  tar -xJf "$CACHE/kata.tar.xz" -C "$CACHE" "$KERNEL_IN_TAR"
  cp "$CACHE/$KERNEL_IN_TAR" "$CACHE/vmlinux"; rm -rf "$CACHE/opt" "$CACHE/kata.tar.xz"
fi
echo "kernel sha256: $(shasum -a 256 "$CACHE/vmlinux" | cut -d' ' -f1)"
file "$CACHE/vmlinux" | grep -q "ARM64 boot executable" || { echo "kernel is not a raw arm64 Image"; exit 1; }

APP=build/Localite.app; rm -rf build; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
echo "==> Compiling Swift app"
swiftc -O -target arm64-apple-macos12.0 -o "$APP/Contents/MacOS/Localite" \
  main.swift WorkspaceDisk.swift AWSWorkbench.swift \
  -framework Cocoa -framework Virtualization
cp Info.plist "$APP/Contents/Info.plist"
cp "$CACHE/vmlinux" "$APP/Contents/Resources/vmlinux"
cp ../guest/initrd.gz "$APP/Contents/Resources/initrd.gz"
cp Resources/logo.png "$APP/Contents/Resources/logo.png"

echo "==> Building icon"
IS=build/AppIcon.iconset; mkdir -p "$IS"
for s in 16 32 128 256 512; do
  sips -z $s $s Resources/icon-1024.png --out "$IS/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) Resources/icon-1024.png --out "$IS/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$IS" -o "$APP/Contents/Resources/AppIcon.icns"

echo "==> Signing (ad-hoc, with virtualization entitlement)"
codesign --force --deep --sign - --entitlements Localite.entitlements "$APP"

echo "==> Building DMG"
STAGE=build/dmg; mkdir -p "$STAGE"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname Localite -srcfolder "$STAGE" -ov -format UDZO build/Localite.dmg >/dev/null
echo "Done: $(pwd)/build/Localite.dmg"
echo "Open it, drag Localite to Applications. (Built locally, so Gatekeeper won't quarantine it.)"
