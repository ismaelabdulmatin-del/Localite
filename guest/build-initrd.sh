#!/usr/bin/env bash
# Build the static aarch64 Linux guest initramfs.
# Linux: requires rust-src and the GNU aarch64 cross toolchain.
# macOS: install the aarch64-unknown-linux-musl Rust target and Zig, then set ZIG=/path/to/zig.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.."
export RUSTFLAGS="-C target-feature=+crt-static"

if [ "$(uname -s)" = Darwin ]; then
  TARGET=aarch64-unknown-linux-musl
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$HERE/aarch64-linux-musl-linker.sh"
  cargo build --release -p localite-sandbox --target "$TARGET"
else
  TARGET=aarch64-unknown-linux-gnu
  export RUSTC_BOOTSTRAP=1
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  cargo build --release -p localite-sandbox --target "$TARGET" -Zbuild-std=std,panic_abort
fi

W=$(mktemp -d)
trap 'rm -rf -- "$W"' EXIT
cp "target/$TARGET/release/localite-sandbox" "$W/init"
chmod 755 "$W/init"
python3 "$HERE/fetch-moto-rootfs.py" "$W/moto-rootfs"
python3 "$HERE/make-initrd.py" "$W/init" "$HERE/initrd.gz" "$W/moto-rootfs"
