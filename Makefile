# ============================================================
#  Makefile – Bare-metal OS with Bochs CPU emulation + BusyBox
# ============================================================

ISODIR   := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN     := main.iso
DISK_IMG := disk.img

# ── Compiler flags ───────────────────────────────────────────
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra \
            -fno-use-cxa-atexit -std=c++17    \
            -fno-exceptions -fno-rtti -m32    \
            -fno-stack-protector              \
            -fno-pie -fno-pic                 \
            -include fixes.h                  \
            -include instrument_stub.h

# ── Bochs 2.7 ────────────────────────────────────────────────
BOCHS_VERSION   := 2.7
BOCHS_DIR       := bochs-$(BOCHS_VERSION)
BOCHS_ARCHIVE   := $(BOCHS_DIR).tar.gz
BOCHS_URL       := https://downloads.sourceforge.net/project/bochs/bochs/$(BOCHS_VERSION)/$(BOCHS_ARCHIVE)
BOCHS_CPU_LIB   := $(BOCHS_DIR)/cpu/libcpu.a

# ── BusyBox 32-bit static (musl) ─────────────────────────────
BUSYBOX_URL := https://busybox.net/downloads/binaries/1.35.0-i686-linux-musl/busybox
BUSYBOX_BIN := busybox

# ── Lynx text-mode web browser ───────────────────────────────
# Built from source (no canonical prebuilt static i686 binary exists).
# Run `make setup` once to download + extract + build a static 32-bit
# binary; subsequent `make` invocations pick up $(LYNX_BIN) automatically
# via lynx_blob.o's wildcard dependency.
LYNX_VERSION := 2.9.2
LYNX_DIR     := lynx2-9-2
LYNX_ARCHIVE := lynx$(LYNX_VERSION).tar.bz2
LYNX_URL     := https://invisible-mirror.net/archives/lynx/tarballs/$(LYNX_ARCHIVE)
LYNX_BIN     := $(LYNX_DIR)/lynx

# ============================================================
#  Top-level targets
# ============================================================
all: $(MAIN) $(DISK_IMG)

# ── Disk image ────────────────────────────────────────────────
# 128 MB FAT32 image, 8 sectors/cluster, 32 reserved sectors.
# Built by mkfat32.py (pure Python, no dosfstools package needed).
# Created once; preserved across builds so filesystem state survives reboots.
$(DISK_IMG):
	@echo ">>> Creating 128 MB FAT32 disk image (no external tools needed)..."
	python3 mkfat32.py $(DISK_IMG) 128
	@echo ">>> $(DISK_IMG) ready."

iso: $(MULTIBOOT)
	mkdir -p iso/boot/grub
	printf '%s\n'                                                 \
	    'set timeout=3'                                           \
	    'set default=0'                                           \
	    'insmod all_video'                                        \
	    'insmod vbe'                                              \
	    'insmod vga'                                              \
	    'insmod gfxterm'                                          \
	    'terminal_input  console'                                 \
	    'terminal_output console'                                 \
	    'menuentry "RTOS++" {'                                    \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    'menuentry "RTOS++ (text console only)" {'                \
	    '    set gfxpayload=text'                                 \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue --product-name="RTOS++" -o main.iso iso -- -volid RTOSPP
	@echo ">>> ISO ready: main.iso"


clean:
	rm -rf *.o main.iso iso hello hello_blob.o lynx_payload

# distclean removes build artifacts and the disk image, but KEEPS the
# prebuilt bochs-2.7/ tree (see note in recipe).
distclean: clean
	# NOTE: the prebuilt bochs-2.7/ tree is intentionally NOT removed,
	#       so the offline bundle stays buildable. Remove it by hand to
	#       force a fresh download + configure on the next build.
	# The lynx tree IS removed here because, unlike Bochs, it has no
	# "prebuilt offline bundle" status — it's purely opt-in via setup.
	rm -rf $(BOCHS_ARCHIVE) ramdisk.o $(DISK_IMG) \
	       $(LYNX_ARCHIVE) $(LYNX_DIR)

.PHONY: all clean distclean iso test_main run-test setup lynx

# ============================================================
#  Bochs CPU/FPU/cpudb/memory static libraries
# ------------------------------------------------------------
#  OFFLINE BUNDLE: this tree ships with bochs-2.7/ already
#  configured and with the four static libs prebuilt
#  (cpu/libcpu.a, cpu/fpu/libfpu.a, cpu/cpudb/libcpudb.a,
#  memory/libmemory.a). When those libs are present "make"
#  uses them directly and performs NO download / configure.
#
#  If the prebuilt libs are absent, the rule falls back to the
#  original behaviour: download the tarball, extract, configure
#  --with-nogui, and build the four libs.
# ============================================================
$(BOCHS_ARCHIVE):
	wget -O $@ "$(BOCHS_URL)" || curl -L -o $@ "$(BOCHS_URL)"

$(BOCHS_DIR)/.extracted: $(BOCHS_ARCHIVE)
	tar -xzf $(BOCHS_ARCHIVE)
	touch $@

# libcpu.a is prebuilt in the offline bundle. The download+configure
# +build recipe only runs if the file is genuinely missing.
$(BOCHS_CPU_LIB):
	@if [ -f "$(BOCHS_CPU_LIB)" ]; then \
	    echo ">>> Using prebuilt Bochs libs in $(BOCHS_DIR) (offline bundle)."; \
	else \
	    echo ">>> Prebuilt Bochs libs not found - downloading and building..."; \
	    $(MAKE) $(BOCHS_DIR)/.extracted; \
	    cd $(BOCHS_DIR) && ./configure \
	        --enable-cpu-level=6 --enable-fpu --with-nogui \
	        --host=i686-linux-gnu --enable-x86-64 \
	        CXXFLAGS="-O2 -m32 -fno-stack-protector -fno-pie" \
	        CFLAGS="-O2 -m32 -fno-stack-protector -fno-pie" && cd ..; \
	    $(MAKE) -C $(BOCHS_DIR)/cpu; \
	    $(MAKE) -C $(BOCHS_DIR)/cpu/fpu; \
	    $(MAKE) -C $(BOCHS_DIR)/cpu/cpudb; \
	    $(MAKE) -C $(BOCHS_DIR)/memory; \
	fi



# Bochs instrument stub header (required by bochs_glue.cpp).
# Prebuilt bundle already contains it; re-copying is harmless.
$(BOCHS_DIR)/instrument.h:
	cp instrument_stub.h $@

# ============================================================
#  BusyBox ramdisk
# ============================================================
$(BUSYBOX_BIN):
	@echo ">>> Downloading BusyBox i686 static binary..."
	wget -O $@ "$(BUSYBOX_URL)" || curl -L -o $@ "$(BUSYBOX_URL)"
	chmod +x $@
	@echo ">>> BusyBox downloaded."

# Embed BusyBox as read-only data in the kernel ELF.
# IMPORTANT: -B i386 (not i386:x86-64) for a 32-bit kernel binary.
ramdisk.o: $(BUSYBOX_BIN)
	@echo ">>> Embedding BusyBox into ramdisk.o..."
	objcopy \
	    -I binary \
	    -O elf32-i386 \
	    -B i386 \
	    --rename-section .data=.rodata,alloc,load,readonly,data,contents \
	    --redefine-sym _binary_busybox_start=ramdisk_start \
	    --redefine-sym _binary_busybox_end=ramdisk_end   \
	    --redefine-sym _binary_busybox_size=ramdisk_size  \
	    $(BUSYBOX_BIN) $@
	@echo ">>> ramdisk.o created."

# Tiny test ELF that prints "HELLO\n" via port 0xE9 and halts.
# Used to verify the GDT/IDT/port-IO chain end-to-end without dragging
# in busybox's full Linux ABI requirements.
hello: hello.c
	@echo ">>> Building hello test ELF..."
	gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
	    -Wl,-Ttext=0x08048000 \
	    -o $@ hello.c
	@echo ">>> hello built."

# Embed the hello ELF as a second blob with its own symbols.
hello_blob.o: hello
	@echo ">>> Embedding hello into hello_blob.o..."
	objcopy \
	    -I binary \
	    -O elf32-i386 \
	    -B i386 \
	    --rename-section .data=.rodata,alloc,load,readonly,data,contents \
	    --redefine-sym _binary_hello_start=hello_start \
	    --redefine-sym _binary_hello_end=hello_end   \
	    --redefine-sym _binary_hello_size=hello_size  \
	    hello $@
	@echo ">>> hello_blob.o created."

# ============================================================
#  Lynx text web browser
# ------------------------------------------------------------
#  Lynx is built from source because no canonical prebuilt
#  static-i686 binary exists. The build chain is opt-in:
#
#    make setup          # download + extract + build static lynx
#    make                # picks up $(LYNX_BIN) and re-embeds it
#
#  On a fresh checkout where setup hasn't been run, lynx_blob.o
#  embeds a tiny "NOLYNX" stub instead — the kernel's
#  extract_lynx_to_filesystem() rejects it (size + ELF magic
#  check) and the `lynx` command prints a friendly "run make
#  setup" message. This keeps the default build offline-safe.
#
#  Build deps (in addition to the compile.md list):
#    libncurses-dev        # ncurses with static archives
#  On a 64-bit host targeting 32-bit, you may also need:
#    libncurses-dev:i386   # multi-arch static ncurses for i386
#  installed via `dpkg --add-architecture i386 && apt update`.
# ============================================================
$(LYNX_ARCHIVE):
	@echo ">>> Downloading Lynx $(LYNX_VERSION) source..."
	wget -O $@ "$(LYNX_URL)" || curl -L -o $@ "$(LYNX_URL)"

$(LYNX_DIR)/.extracted: $(LYNX_ARCHIVE)
	@echo ">>> Extracting Lynx source into $(LYNX_DIR)/..."
	# Don't assume what the tarball's top-level directory is called
	# (e.g. lynx2.9.2/ vs lynx-2.9.2/ vs lynx2-9-2/). Create our own
	# destination directory and use --strip-components=1 to flatten
	# whatever's inside into it. Works for any inner naming convention.
	mkdir -p $(LYNX_DIR)
	tar -xjf $(LYNX_ARCHIVE) -C $(LYNX_DIR) --strip-components=1
	touch $@

# Patch Lynx 2.9.2 source for modern toolchains (gcc 13+, glibc 2.36+,
# ncurses 6.x with opaque WINDOW). Each sed is idempotent (no-op if the
# offending line is already gone), so re-running `make setup` after a
# fresh `rm -rf $(LYNX_DIR)` is safe, and so is running it on a tree
# that was already half-patched.
#
# Stamp-name convention: bump the suffix (.patched-r2, .patched-r3, ...)
# whenever new patches are added. Make compares timestamps, not recipe
# contents, so a renamed stamp is the cleanest way to force re-application
# on a tree that already has an older stamp from a previous build round.
$(LYNX_DIR)/.patched-r4: $(LYNX_DIR)/.extracted
	@echo ">>> Patching Lynx source for modern glibc/gcc/ncurses..."
	# (1) Drop Lynx's local putenv() prototype — it declares the arg as
	#     `const char *`, glibc's stdlib.h declares it as `char *`, and
	#     modern gcc treats the mismatch as a hard error (not a warning).
	#     The system header already provides the correct declaration.
	sed -i '/extern int putenv(const char \*string);/d' $(LYNX_DIR)/src/LYUtils.h
	# (2) Drop Lynx's broken fallback macros in LYCurses.h that poke at
	#     WINDOW internals (e.g. `#define getbegx(win) ((win)->_begx)`).
	#     Modern ncurses keeps WINDOW opaque, so those struct accesses
	#     don't compile. Removing the lines lets ncurses's own
	#     getbegx/getbegy/getmaxx/getmaxy/getparx/getpary functions take
	#     effect (libncurses always provides them as real symbols).
	sed -i '/^#define[ \t][ \t]*get[a-z]*(win)[ \t][ \t]*((win)->_[a-z]*)$$/d' $(LYNX_DIR)/src/LYCurses.h
	# (3) Realign Lynx's putenv() compat shim definition in LYUtils.c to
	#     match glibc's signature (`char *` instead of `const char *`).
	#     The shim is supposed to be skipped when HAVE_PUTENV is set, but
	#     autoconf's detection sometimes fails on modern toolchains and
	#     the shim ends up compiled. Matching glibc's signature lets it
	#     coexist instead of erroring out.
	sed -i 's|^int putenv(const char \*string)$$|int putenv(char *string)|' $(LYNX_DIR)/src/LYUtils.c
	# (4) Same treatment for Lynx's remove() compat shim — change the
	#     parameter to `const char *` to match glibc's signature.
	#     Lynx's shim body only calls unlink/rmdir (both already take
	#     const char *), so adding const is safe.
	sed -i 's|^int remove(char \*name)$$|int remove(const char *name)|' $(LYNX_DIR)/src/LYUtils.c
	# (5) glibc 2.34+ removed the `sys_nerr` and `sys_errlist` globals
	#     (they were deprecated in 2.32). Lynx 2.9.2's HTTCP.c still
	#     references them. Replace `sys_errlist[X]` with `strerror(X)`
	#     and `sys_nerr` with `INT_MAX` (the bound check `errno<sys_nerr`
	#     becomes a tautology, which is fine because strerror handles
	#     out-of-range errno values itself by returning a fallback).
	sed -i 's|sys_errlist\[\([^]]*\)\]|strerror(\1)|g' $(LYNX_DIR)/WWW/Library/Implementation/HTTCP.c
	sed -i 's|\bsys_nerr\b|INT_MAX|g' $(LYNX_DIR)/WWW/Library/Implementation/HTTCP.c
	# Make sure HTTCP.c has the headers for strerror() and INT_MAX.
	# (The grep guards keep these idempotent on repeat runs.)
	grep -q '#include <limits.h>' $(LYNX_DIR)/WWW/Library/Implementation/HTTCP.c \
	    || sed -i '1i#include <limits.h>' $(LYNX_DIR)/WWW/Library/Implementation/HTTCP.c
	grep -q '#include <string.h>' $(LYNX_DIR)/WWW/Library/Implementation/HTTCP.c \
	    || sed -i '1i#include <string.h>' $(LYNX_DIR)/WWW/Library/Implementation/HTTCP.c
	# (6) Lynx 2.9.2 has source-level inconsistencies where some
	#     `#ifdef USE_FOO` guards a symbol's DEFINITION but not its
	#     references in other files. With --disable-color-style and
	#     friends (which we need to pass to get past configure on this
	#     toolchain), the references go unresolved at link time. Provide
	#     zero / no-op stubs at the end of LYUtils.c (which is always
	#     compiled+linked) so the link can complete. Each stub is a
	#     functional no-op — lynx still runs, it just skips the
	#     corresponding optional feature.
	@if ! grep -q "LYNX_MODERN_STUBS" $(LYNX_DIR)/src/LYUtils.c; then \
	    echo ">>> Appending modern-toolchain stubs to LYUtils.c..."; \
	    printf '\n%s\n' \
	        '/* === LYNX_MODERN_STUBS: appended by OS-main Makefile === */' \
	        '#include <stdlib.h>' \
	        'int  LYuseCursesPads = 0;' \
	        'int  LYShowScrollbar = 0;' \
	        'int  LYsb_arrow      = 0;' \
	        'int  LYwideLines     = 0;' \
	        'void lynx_setup_colors(void) {}' \
	        'void LYExtSignal(int sig) { (void)sig; }' \
	        'long long LYatoll(const char *s) { return atoll(s); }' \
	        '/* === end LYNX_MODERN_STUBS === */' \
	        >> $(LYNX_DIR)/src/LYUtils.c; \
	fi
	touch $@

# Configure + build a minimal static 32-bit lynx. SSL is disabled because
# the kernel has no TCP/IP stack; lynx is still useful for local HTML.
# A few rarely-used protocols are disabled to shrink the binary.
$(LYNX_BIN): $(LYNX_DIR)/.patched-r4
	@echo ">>> Configuring Lynx (static, 32-bit, no SSL)..."
	cd $(LYNX_DIR) && ./configure \
	    --host=i686-linux-gnu \
	    --with-screen=ncurses \
	    --without-ssl \
	    --without-zlib \
	    --without-bzlib \
	    --disable-color-style \
	    --disable-finger \
	    --disable-gopher \
	    --disable-news \
	    --disable-ftp \
	    --disable-nls \
	    CC="gcc -m32" \
	    CFLAGS="-m32 -O2 -fno-pie \
	            -Wno-error=incompatible-pointer-types \
	            -Wno-error=implicit-function-declaration \
	            -Wno-error=int-conversion" \
	    LDFLAGS="-m32 -static -no-pie -Wl,--allow-multiple-definition"
	@echo ">>> Building Lynx..."
	$(MAKE) -C $(LYNX_DIR)
	-strip $(LYNX_BIN)
	@echo ">>> Lynx built: $(LYNX_BIN)"

# Embed lynx as a kernel blob. The wildcard dep means:
#   - if $(LYNX_BIN) exists at parse time, lynx_payload depends on it
#     and re-embeds whenever the binary is rebuilt;
#   - if not (default state on a fresh checkout), the recipe writes a
#     6-byte "NOLYNX" stub instead, which the kernel-side extractor
#     silently rejects via its ELF-magic + size check.
# Using a fixed intermediate name (lynx_payload) keeps the objcopy
# --redefine-sym arguments stable regardless of where the real binary
# lives in the tree.
lynx_payload: $(wildcard $(LYNX_BIN))
	@if [ -f "$(LYNX_BIN)" ]; then \
	    echo ">>> Lynx binary found — staging as payload..."; \
	    cp "$(LYNX_BIN)" $@; \
	else \
	    echo ">>> Lynx not built yet — embedding stub payload."; \
	    echo ">>> Run 'make setup' to build the real lynx, then rerun make."; \
	    printf 'NOLYNX' > $@; \
	fi

lynx_blob.o: lynx_payload
	@echo ">>> Embedding lynx_payload into lynx_blob.o..."
	objcopy \
	    -I binary \
	    -O elf32-i386 \
	    -B i386 \
	    --rename-section .data=.rodata,alloc,load,readonly,data,contents \
	    --redefine-sym _binary_lynx_payload_start=lynx_start \
	    --redefine-sym _binary_lynx_payload_end=lynx_end   \
	    --redefine-sym _binary_lynx_payload_size=lynx_size  \
	    lynx_payload $@
	@echo ">>> lynx_blob.o created."

# ── One-shot bootstrap: fetch everything needed offline ──────
# Idempotent: re-running `make setup` after a successful run is a no-op
# (or only re-builds what's missing). Run this once on a fresh clone,
# then `make` from then on can build without network access.
setup: $(BUSYBOX_BIN) $(BOCHS_CPU_LIB) $(LYNX_BIN)
	@echo ">>> setup: BusyBox, Bochs libs, and Lynx are all ready."
	@echo ">>> Now run: make"

# Convenience alias: download/build the lynx binary only.
lynx: $(LYNX_BIN)
	@echo ">>> lynx: $(LYNX_BIN) ready. Run 'make' to re-embed and relink."

# ============================================================
#  Bochs CPU emulation: ON by default (set BOCHS=0 to disable)
#  bochs_infra.o provides all Bochs infrastructure globals
#  (logfunctions, SIM, bx_cpu, bx_mem, bx_devices, etc.)
# ============================================================



BOCHS_OBJ    := bochs_glue.o bochs_infra.o bochs_paramtree.o bochs_pc_system.o bochs_cstubs.o setjmp.o test_module.o
BOCHS_LIBS   := $(BOCHS_DIR)/cpu/libcpu.a \
                $(BOCHS_DIR)/cpu/fpu/libfpu.a \
                $(BOCHS_DIR)/cpu/cpudb/libcpudb.a \
                $(BOCHS_DIR)/memory/libmemory.a
BOCHS_IFLAGS := -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu \
                -I$(BOCHS_DIR)/iodev -I$(BOCHS_DIR)/gui
BOCHS_DEP    := $(BOCHS_CPU_LIB)
BOCHS_CDEF   := -DBOCHS_ENABLED=1
LIBGCC_EH    := /usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc_eh.a


# ============================================================
#  Kernel object files
# ============================================================
boot.o: boot.S
	as --32 boot.S -o boot.o

kernel.o: kernel.cpp $(BOCHS_DEP)
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) $(BOCHS_CDEF) -c kernel.cpp -o kernel.o

bochs_stub.o: bochs_stub.cpp
	g++ -m32 -O2 $(CXXFLAGS) -c bochs_stub.cpp -o bochs_stub.o

bochs_glue.o: bochs_glue.cpp $(BOCHS_DIR)/instrument.h $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) -DBOCHS_GLUE -c bochs_glue.cpp -o bochs_glue.o

# bochs_infra.cpp needs system headers (not freestanding) because bochs.h
# pulls in <stdio.h> etc. for its own types. Compiled as a normal 32-bit object.
bochs_infra.o: bochs_infra.cpp $(BOCHS_DIR)/instrument.h $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) \
	    -fno-exceptions -fno-rtti -fno-pie -fno-pic \
	    -std=c++17 \
	    -include instrument_stub.h \
	    -c bochs_infra.cpp -o bochs_infra.o

# bochs_paramtree.o — provides bx_list_c, bx_shadow_num_c, bx_param_num_c etc.
bochs_paramtree.o: $(BOCHS_DIR)/gui/paramtree.cc $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) \
	    -fno-exceptions -fno-rtti -fno-pie -fno-pic \
	    -std=c++17 \
	    -include instrument_stub.h \
	    -c $(BOCHS_DIR)/gui/paramtree.cc -o bochs_paramtree.o

# bochs_pc_system.o — provides bx_pc_system_c constructor and timer methods
bochs_pc_system.o: $(BOCHS_DIR)/pc_system.cc $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) \
	    -fno-exceptions -fno-rtti -fno-pie -fno-pic \
	    -std=c++17 \
	    -include instrument_stub.h \
	    -c $(BOCHS_DIR)/pc_system.cc -o bochs_pc_system.o

# bochs_cstubs.o — freestanding C stdlib stubs (no system headers)
bochs_cstubs.o: bochs_cstubs.c
	gcc -m32 -O2 -ffreestanding -fno-pie -fno-pic \
	    -c bochs_cstubs.c -o bochs_cstubs.o

# setjmp.o — pure-asm i386 setjmp/longjmp/__longjmp_chk matching glibc layout.
# Required by libcpu.a (Bochs' internal exception unwinding) and by
# bochs_glue.cpp's rescue path.
setjmp.o: setjmp.S
	as --32 setjmp.S -o setjmp.o
	
test_module.o: test_module.cpp
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) -c test_module.cpp -o test_module.o

# ============================================================
#  Link
# ============================================================
$(MULTIBOOT): boot.o kernel.o ramdisk.o hello_blob.o lynx_blob.o test_module.o $(BOCHS_OBJ) $(BOCHS_DEP)
	mkdir -p iso/boot
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(MULTIBOOT)              \
	    boot.o kernel.o ramdisk.o hello_blob.o lynx_blob.o $(BOCHS_OBJ) \
	    $(BOCHS_LIBS)                \
	    -lgcc $(LIBGCC_EH)           \
	    -Wl,--allow-multiple-definition

# ============================================================
#  ISO image via GRUB (hybrid BIOS + UEFI)
# ------------------------------------------------------------
#  grub-mkrescue auto-detects the GRUB platforms installed on the
#  build host. With grub-pc-bin installed you get a BIOS-bootable
#  El Torito image; with grub-efi-amd64-bin / grub-efi-ia32-bin also
#  installed you get an additional EFI System Partition embedded
#  in the same ISO, so the output boots on:
#    * QEMU / Bochs                      (BIOS)
#    * VMware Workstation / Fusion       (BIOS or UEFI firmware)
#    * Real bare metal w/ legacy CSM     (BIOS)
#    * Real bare metal UEFI-only         (UEFI)
#
#  See: install with
#    apt-get install grub-pc-bin grub-efi-amd64-bin grub-efi-ia32-bin \
#                    xorriso mtools
# ============================================================
$(MAIN): $(MULTIBOOT)
	mkdir -p iso/boot/grub
	printf '%s\n'                                                 \
	    'set timeout=3'                                           \
	    'set default=0'                                           \
	    'insmod all_video'                                        \
	    'insmod vbe'                                              \
	    'insmod vga'                                              \
	    'insmod gfxterm'                                          \
	    'terminal_input  console'                                 \
	    'terminal_output console'                                 \
	    'menuentry "RTOS++" {'                                    \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    'menuentry "RTOS++ (text console only)" {'                \
	    '    set gfxpayload=text'                                 \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue                                                 \
	    --product-name="RTOS++"                                   \
	    --product-version="1.0"                                   \
	    -o $(MAIN) iso                                            \
	    -- -volid RTOSPP
	@echo ">>> ISO ready: $(MAIN)"
	@if command -v xorriso >/dev/null 2>&1; then \
	    echo "--- Boot record summary ---"; \
	    xorriso -indev $(MAIN) -report_el_torito plain 2>/dev/null \
	        | sed -n '/Boot record/p;/El Torito/p'; \
	    xorriso -indev $(MAIN) -report_system_area plain 2>/dev/null \
	        | sed -n '/System area/p'; \
	fi

# ============================================================
#  test_main — standalone Bochs init + cpu_tick verification
# ------------------------------------------------------------
#  Builds test_main.cpp (which provides its own kernel_main and a
#  two-phase self-test) instead of the full kernel.cpp. Produces a
#  bootable test_main.iso. This is the smallest end-to-end check
#  that the Bochs glue works: Phase 1 runs BX_CPU(0)->initialize()
#  + reset(); Phase 2 loads a tiny guest and ticks it, expecting
#  "HI\n" on the guest port-0xE9 console.
#
#  Run it headless and watch the port-0xE9 trace:
#    make test_main
#    qemu-system-i386 -M q35 -cdrom test_main.iso -boot d \
#        -m 512M -display none -debugcon stdio -no-reboot
#  A passing run prints:  === TEST PASSED (init + tick) ===
#
#  `make run-test` does both steps in one go.
# ============================================================
TEST_ISO   := test_main.iso
TEST_ELF   := iso/boot/main.elf

test_main.o: test_main.cpp $(BOCHS_DEP)
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) $(BOCHS_CDEF) -c test_main.cpp -o test_main.o

# test_main links WITHOUT ramdisk.o / hello_blob.o — the harness
# references none of the busybox/hello blob symbols.
test_main: boot.o test_main.o $(BOCHS_OBJ) $(BOCHS_DEP)
	mkdir -p iso/boot/grub
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(TEST_ELF) \
	    boot.o test_main.o $(BOCHS_OBJ) \
	    $(BOCHS_LIBS) \
	    -lgcc $(LIBGCC_EH) \
	    -Wl,--allow-multiple-definition
	printf '%s\n' \
	    'set timeout=0' \
	    'set default=0' \
	    'menuentry "RTOS++ test_main" {' \
	    '    multiboot /boot/main.elf' \
	    '    boot' \
	    '}' \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue -o $(TEST_ISO) iso
	@echo ">>> $(TEST_ISO) ready. Boot it with -debugcon stdio to see the trace."

run-test: test_main
	qemu-system-i386 -M q35 -cdrom $(TEST_ISO) -boot d \
	    -m 512M -display none -debugcon stdio -no-reboot
