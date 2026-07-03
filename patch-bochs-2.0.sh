#!/bin/sh
# patch-bochs-2.0.sh — fix Bochs 2.0 (2003) source to build with a
# modern GCC/glibc toolchain. Run once, right after extracting the
# tarball and before ./configure. Idempotent (safe to re-run).
#
# Usage: ./patch-bochs-2.0.sh <bochs-2.0-dir>
set -e
DIR="$1"
if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
    echo "usage: $0 <bochs-2.0-source-dir>" >&2
    exit 1
fi
SENTINEL="$DIR/.claude-patched"
if [ -f "$SENTINEL" ]; then
    echo ">>> $DIR already patched, skipping."
    exit 0
fi

echo ">>> Patching $DIR for modern-toolchain compatibility..."

# ------------------------------------------------------------------
# Fix 1 & 2: fpu/stubs/linux/types.h and fpu/stubs/asm/types.h shadow
# the real system <linux/types.h> / <asm/types.h> (they claim the
# same include guard without providing the __u64/__s64/etc typedefs
# that modern glibc's <bits/statx.h> needs). Bochs wrote these in
# 2003 for platforms lacking Linux kernel headers; on a real Linux
# host they must fall through to the real headers instead.
# ------------------------------------------------------------------
cat > "$DIR/fpu/stubs/linux/types.h" << 'EOF'
#if defined(__linux__)
/* On a real Linux host the system already has a complete, correct
 * <linux/types.h> (needed transitively by modern glibc's
 * <bits/statx.h> for __u64/__s64/etc). This 2003-era stub predates
 * that dependency; it used to define the SAME include guard
 * (_LINUX_TYPES_H) as the real header without providing those
 * typedefs, which made the real header effectively unreachable
 * (its own guard already looked "claimed") and left __u64 etc.
 * undefined. Fix: let the real header claim its own guard via
 * #include_next FIRST, then add bochs's extra BSD-style aliases
 * below under a different guard so we never collide again. */
#include_next <linux/types.h>
#endif

#ifndef _BX_LINUX_TYPES_STUB_H
#define _BX_LINUX_TYPES_STUB_H

#ifndef __ASSEMBLY__

#define u_char bx_u_char
#define u_short bx_u_short
#define u_int bx_u_int
#define u_long bx_u_long
#define unchar bx_unchar
#define ushort bx_ushort
#define uint bx_uint
#define ulong bx_ulong

/* bsd */
typedef unsigned char           u_char;
typedef unsigned short          u_short;
typedef unsigned int            u_int;
typedef unsigned long           u_long;

/* sysv */
typedef unsigned char           unchar;
typedef unsigned short          ushort;
typedef unsigned int            uint;
typedef unsigned long           ulong;

#ifndef NULL
#define NULL ((void *) 0)
#endif

#endif

#endif /* _BX_LINUX_TYPES_STUB_H */
EOF

cat > "$DIR/fpu/stubs/asm/types.h" << 'EOF'
#ifndef _I386_TYPES_H
#define _I386_TYPES_H

#ifndef __ASSEMBLY__
#if defined(__linux__)
/* Same issue as fpu/stubs/linux/types.h: this 2003-era empty stub
 * shadows the real system <asm/types.h> (which defines __u64/__s64/
 * etc) via -I./stubs coming before the system include path. Fall
 * through to the real header instead of silently providing nothing. */
#include_next <asm/types.h>
#endif
#endif

#endif  /* _I386_TYPES_H */
EOF

# ------------------------------------------------------------------
# Fix 3: bochs's own top-level debug/ directory (the interactive
# debugger subsystem) contains a debug.h file that collides with
# libstdc++'s own <debug/debug.h> (used internally by <bits/
# stl_algobase.h> for iterator debug-mode declarations). Because -I..
# puts the bochs root on the include path, any C++ file that pulls in
# <math.h>/<cmath> ends up finding BOCHS's debug/debug.h instead of
# the real system one, which silently drops the forward declaration
# of "namespace __gnu_debug" and breaks the STL headers with
# confusing "expected initializer before '<' token" errors.
# GCC always prefers its own default system dirs' *position* for
# paths that match them, so reordering -I flags cannot fix this - the
# colliding filename has to go. Renaming just the file (not the
# whole debug/ directory, which configure's AC_OUTPUT still expects
# to find at that path) is the minimal fix.
# ------------------------------------------------------------------
if [ -f "$DIR/debug/debug.h" ]; then
    mv "$DIR/debug/debug.h" "$DIR/debug/bxdebug.h"
    sed -i 's#include "debug/debug\.h"#include "debug/bxdebug.h"#' "$DIR/bochs.h"
    # Update the (non-functional, dependency-tracking-only) Makefile.in
    # references too, so `make` doesn't choke looking for a rule to
    # build a file that no longer exists.
    grep -rl "debug/debug\.h" "$DIR"/*/Makefile.in "$DIR"/Makefile.in 2>/dev/null | \
        xargs -r sed -i 's#debug/debug\.h#debug/bxdebug.h#g'
fi

# ------------------------------------------------------------------
# Fix 4: fpu/stubs/linux/linkage.h's "asmlinkage" macro adds
# __attribute__((regparm(0))) on i386, mimicking the Linux kernel's
# calling convention for asmlinkage functions. fpu_proto.h declares
# functions like arith_overflow() WITHOUT this attribute, but the
# corresponding definitions in errors.c use "asmlinkage" and so
# DO have it. Older GCC tolerated the mismatch; GCC 13 treats a
# regparm difference between a declaration and its definition as a
# hard "conflicting types" error. Since fpu/ here is a plain
# userspace static library (not linked against real kernel object
# code), the kernel-ABI attribute serves no purpose - drop it.
# ------------------------------------------------------------------
if [ -f "$DIR/fpu/stubs/linux/linkage.h" ]; then
    sed -i \
        's/^#if defined __i386__ \&\& (__GNUC__ > 2 || __GNUC_MINOR__ > 7)$/#if 0 \&\& defined __i386__ \&\& (__GNUC__ > 2 || __GNUC_MINOR__ > 7) \/* regparm(0) disabled: see patch-bochs-2.0.sh *\//' \
        "$DIR/fpu/stubs/linux/linkage.h"
fi

# ------------------------------------------------------------------
# Fix 5: configure's readline detection ("checking if readline works
# without/with -lcurses") uses AC_TRY_RUN, which needs to actually
# EXECUTE a compiled 32-bit test program. Passing --host=i686-linux-gnu
# doesn't by itself make autoconf refuse this (it decides based on
# whether a compiled test binary actually runs, not on the --host
# string), but on hosts that can compile 32-bit binaries yet can't
# execute them (e.g. no i386 execution support at all), autoconf
# concludes "yes, cross compiling" and this specific check - unlike
# most autoconf checks - has no cross-compile fallback, so it hard-
# aborts configure with "cannot run test program while cross
# compiling" instead of just answering "no" like everything else does.
# We don't use the interactive debugger (and therefore never need
# readline) in this headless build, so just make these two checks
# fall through and try execution unconditionally; if the binary can't
# run they land on the same "no" result this would have produced
# anyway, without the hard abort.
# ------------------------------------------------------------------
if [ -f "$DIR/configure" ]; then
    python3 - "$DIR/configure" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
marker = 'if test "$cross_compiling" = yes; then'
# Scope strictly to the readline test program (rl_initialize), not the
# generic cross-compile error text, which is shared boilerplate used
# by many OTHER AC_TRY_RUN checks in this configure script (sizeof,
# endianness, etc.) that must keep failing loudly if they can't
# actually execute a test binary - only readline's is safe to skip.
needle = 'rl_initialize'
count = 0
out = []
i = 0
while True:
    j = text.find(marker, i)
    if j == -1:
        out.append(text[i:])
        break
    window = text[j:j+600]
    if needle in window:
        out.append(text[i:j])
        out.append('if false; then')
        count += 1
        i = j + len(marker)
    else:
        out.append(text[i:j+len(marker)])
        i = j + len(marker)
with open(path, 'w') as f:
    f.write(''.join(out))
print(f">>> neutralized {count} readline cross-compile check(s) in configure")
if count != 2:
    print(f"WARNING: expected exactly 2 readline checks, neutralized {count} - verify configure.in structure hasn't changed")
PYEOF
fi

touch "$SENTINEL"
echo ">>> Patching complete."
