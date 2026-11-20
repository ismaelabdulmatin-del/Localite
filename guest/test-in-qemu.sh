#!/usr/bin/env bash
# Boot the real guest kernel + initrd under QEMU (TCG) and run the full self-test inside it.
# Usage: guest/test-in-qemu.sh /path/to/vmlinux   (the Kata arm64 kernel Image; see app/build-dmg.sh)
set -euo pipefail
cd "$(dirname "$0")"
timeout 300 qemu-system-aarch64 -M virt -cpu cortex-a72 -m 1024 -smp 2 -nographic -no-reboot \
  -kernel "${1:?kernel path}" -initrd initrd.gz \
  -append "console=ttyAMA0 rdinit=/init localite.selftest quiet loglevel=3" | tr -d '\r'
