#!/usr/bin/env bash
set -euo pipefail
: "${ZIG:?Set ZIG to the Zig executable path for macOS cross-builds}"
args=()
for arg in "$@"; do
    case "$arg" in
        -Wl,--fix-cortex-a53-843419) ;;
        */self-contained/crt1.o|*/self-contained/crti.o|*/self-contained/crtbegin.o|\
        */self-contained/crtend.o|*/self-contained/crtn.o) ;;
        *) args+=("$arg") ;;
    esac
done
exec "$ZIG" cc -nostdlib -target aarch64-linux-musl "${args[@]}"
