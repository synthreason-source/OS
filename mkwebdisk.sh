#!/bin/sh
# mkwebdisk.sh -- put the web renderer, the text editor, the driver kit,
# all guest headers and some sample pages onto the FAT32 disk image.
#
#   sh mkwebdisk.sh [disk.img]          (default: disk.img)
#   make webdisk                         (same thing, via the Makefile)
#
# What lands in the image root (long names are written as VFAT LFN
# entries by mcopy, exactly like `make cc` does for bochs_drivers.h):
#   headers  : drivers.h bochs_drivers.h driver.h comp.h font.h
#              gui_scene.h gui_render.h
#   sources  : web.c editf.c driverkit.c      (so `cc web.c` works in the OS)
#   programs : web editf driverkit             (prebuilt 32-bit ELFs)
#   pages    : www/*.htm  ->  home.htm about.htm help.htm test.htm
#
# Programs are built the same way `make cc` / compile.md describe:
#   i386-tcc -c -nostdlib  ->  ld -m elf_i386 -T tcc_guest.ld
# Needs: mtools, binutils (ld with elf_i386), i386-tcc (make setup-tcc).
set -e
cd "$(dirname "$0")"

IMG=${1:-disk.img}
export MTOOLS_SKIP_CHECK=1

HEADERS="drivers.h bochs_drivers.h driver.h comp.h font.h gui_scene.h gui_render.h"
SOURCES="web.c editf.c driverkit.c"
PROGS="web editf driverkit"

# i386-tcc: local build first (make setup-tcc), then PATH.  TCC_B may point
# at an uninstalled tcc source tree (passed as -B).
TCC=${TCC:-tcc-local/bin/i386-tcc}
[ -x "$TCC" ] || TCC=$(command -v i386-tcc || true)
[ -n "$TCC" ] || { echo "ERROR: i386-tcc not found. Run: make setup-tcc"; exit 1; }
TCCFLAGS=""
[ -n "$TCC_B" ] && TCCFLAGS="-B $TCC_B"
command -v mcopy >/dev/null || { echo "ERROR: mtools (mcopy) not installed"; exit 1; }

# 1. the image itself
if [ ! -f "$IMG" ]; then
    if [ -f disk.img.xz ]; then
        echo ">>> unpacking disk.img.xz -> $IMG"
        xz -dkc disk.img.xz > "$IMG"
    else
        echo ">>> creating blank 128 MB FAT32 $IMG"
        python3 mkfat32.py "$IMG" 128
    fi
fi

# 2. build the guest programs
mkdir -p build
for p in $PROGS; do
    echo ">>> building $p"
    "$TCC" $TCCFLAGS -c -nostdlib -I. -o "build/$p.o" "$p.c"
    ld -m elf_i386 -static -nostdlib -T tcc_guest.ld -o "build/$p" "build/$p.o" 2>/dev/null
done

# 3. copy everything in (-o = overwrite, so re-running updates the image)
echo ">>> writing files into $IMG"
for f in $HEADERS $SOURCES www/*.htm; do
    mcopy -o -i "$IMG" "$f" "::$(basename "$f")"
done
for p in $PROGS; do
    mcopy -o -i "$IMG" "build/$p" "::$p"
done

echo ">>> contents of $IMG:"
mdir -i "$IMG" ::
echo ">>> done. Boot the OS and run:  web   (or: editf, driverkit, cc web.c)"
