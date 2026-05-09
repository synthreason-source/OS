#!/usr/bin/env bash
# build.sh — build the patched RTOS++ from a clean checkout.
# Run from the directory containing this script.

set -euo pipefail

# ── 1. Check toolchain ──────────────────────────────────────────────────────
need() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1 — apt-get install $2"; exit 1; }
}
need gcc          gcc-multilib
need g++          g++-multilib
need as           binutils
need grub-mkrescue grub-pc-bin
need xorriso      xorriso
need wget         wget
need python3      python3

# ── 2. Check libgcc_eh.a exists (32-bit) ────────────────────────────────────
LIBGCC_EH=$(find /usr/lib/gcc -name libgcc_eh.a -path '*/32/*' 2>/dev/null | head -1)
if [[ -z "$LIBGCC_EH" ]]; then
    echo "32-bit libgcc_eh.a not found — apt-get install gcc-multilib g++-multilib"
    exit 1
fi
echo "Using libgcc_eh.a: $LIBGCC_EH"

# Patch the Makefile if it has a hard-coded path that doesn't match.
if grep -q "/usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc_eh.a" Makefile; then
    if [[ "$LIBGCC_EH" != "/usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc_eh.a" ]]; then
        echo "Patching Makefile LIBGCC_EH path..."
        sed -i "s|/usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc_eh.a|$LIBGCC_EH|g" Makefile
    fi
fi

# ── 3. Make sure mkfat32.py is present (or stub it) ────────────────────────
if [[ ! -f mkfat32.py ]]; then
    echo "Note: mkfat32.py not in tree — only needed for 'make run' (creates disk.img)."
    echo "      Skipping; the kernel still boots without a disk image."
fi

# ── 4. Build ────────────────────────────────────────────────────────────────
echo "Building (this downloads bochs-2.7.tar.gz on first run; takes a few minutes)..."
make -j"$(nproc)" iso

echo
echo "==============================================="
echo "  ISO ready: $(pwd)/main.iso"
echo "  Run with: make run"
echo "==============================================="
