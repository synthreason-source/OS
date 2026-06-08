# =============================================================================
# Makefile — Freestanding kernel with optional Bochs + TCC integration.
#
# Uses the HOST g++ with -m32 — no i686-elf cross-compiler needed.
# Install prerequisites on Ubuntu/Debian:
#   sudo apt install gcc g++ gcc-multilib g++-multilib binutils \
#                    nasm mtools wget make
#
# Quick start:
#   make              — build kernel (TCC stub, no download needed)
#   make TCC=1        — build kernel with real TCC glue; downloads and builds
#                       TCC 0.9.27 automatically if libtcc.so is missing.
#   make fat TCC=1    — copy libtcc.so into the FAT32 disk image
#   make all TCC=1    — build kernel AND copy libtcc.so to disk image
# =============================================================================

# ── Toolchain — host gcc/g++ with -m32, no cross-compiler needed ─────────────
#
# Override on the command line if you DO have a cross-compiler:
#   make CXX=i686-elf-g++ CC=i686-elf-gcc LD=i686-elf-ld CROSS=1
#
CXX     := g++
CC      := gcc
LD      := ld
NASM    := nasm
OBJCOPY := objcopy
STRIP   := strip

# ── Build flags ───────────────────────────────────────────────────────────────
#
# Key decisions:
#
#  -m32
#      Emit i386 (32-bit) code.  Critical: makes sizeof(void*)==4, which
#      matches the kernel's own  typedef unsigned int uintptr_t;  and all
#      the pointer<->int casts throughout the code.  Without -m32 those
#      casts produce "loses precision" hard errors.
#
#  -ffreestanding
#      Do not assume a hosted C library.  The kernel supplies its own
#      strlen, memcpy, new, etc.
#
#  -nostdlib
#      Don't link CRT start files or libgcc automatically.
#      (We pass our own kernel.ld linker script.)
#
#  NOTE: we do NOT pass -nostdinc.
#      The kernel #includes <cstdarg> / <cstddef> / <cstdint> for va_list
#      and NULL.  Those headers are part of the compiler's freestanding
#      support (they live under $(gcc -print-file-name=include)) and work
#      fine with -ffreestanding.  Blocking them with -nostdinc just breaks
#      va_list without any benefit, because the kernel already re-typedefs
#      every integer type itself.
#
#  -fpermissive
#      The kernel intentionally casts string/function pointers to int
#      (e.g. TCompiler::emit4((int)p)) because it targets i386 where
#      pointers ARE 32-bit ints.  -m32 makes those casts safe; -fpermissive
#      silences the remaining front-end complaints about them.
#      Note: -Wno-pointer-to-int-cast and -Wno-int-to-pointer-cast are
#      C/ObjC-only flags; g++ rejects them with a warning.  -fpermissive
#      is the correct C++ equivalent for suppressing these diagnostics.
#
M32      := -m32

CXXFLAGS := $(M32) -std=c++17 -O2 \
            -ffreestanding -fno-exceptions -fno-rtti \
            -fno-stack-protector -nostdlib \
            -fpermissive \
            -Wall -Wextra -Wno-unused-parameter \
            -Wno-ignored-qualifiers

CFLAGS   := $(M32) -std=c11 -O2 \
            -ffreestanding -fno-stack-protector -nostdlib \
            -Wall -Wextra -Wno-unused-parameter

# ld on an x86_64 host: -melf_i386 selects the i386 ELF emulation.
# If using i686-elf-ld, drop -melf_i386 (it is the default for that target).
LDFLAGS  := -T kernel.ld --oformat=elf32-i386 -melf_i386 \
            --allow-multiple-definition

# ── Output ────────────────────────────────────────────────────────────────────
KERNEL_ELF := kernel.elf
DISK_IMG   := disk.img          # FAT32 disk image (for mcopy / Bochs)

# =============================================================================
# TCC integration — select glue vs stub at build time.
#
#   make TCC=0   (default) — link tcc_stub.o; no libtcc needed at all.
#   make TCC=1             — link tcc_glue.o; downloads + builds TCC if needed.
# =============================================================================
TCC ?= 0

TCC_VERSION   := 0.9.27
TCC_TARBALL   := tcc-$(TCC_VERSION).tar.bz2
TCC_URL       := https://download.savannah.gnu.org/releases/tinycc/$(TCC_TARBALL)
TCC_SRC_DIR   := tcc-$(TCC_VERSION)
TCC_BUILD_DIR := tcc-build-i386
LIBTCC_SO     := $(TCC_BUILD_DIR)/libtcc.so

ifeq ($(TCC),1)
  TCC_OBJ    := tcc_glue.o
  TCCFLAGS   := -DTCC_GLUE
  # tcc_glue.o does NOT link against libtcc at kernel-link time.
  # libtcc.so is loaded manually from FAT32 at runtime by tcc_module_init().
  # libtcc_embed.o provides libtcc_start/libtcc_end via objcopy.
  TCC_EXTRA  := libtcc_embed.o
else
  TCC_OBJ    := tcc_stub.o
  TCCFLAGS   :=
  TCC_EXTRA  :=
endif

# =============================================================================
# Bochs integration (same pattern — keeps the existing build working)
# =============================================================================
BOCHS ?= 0

ifeq ($(BOCHS),1)
  BOCHS_OBJ  := bochs_glue.o
  BOCHSFLAGS := -DBOCHS_GLUE
else
  BOCHS_OBJ  := bochs_stub.o
  BOCHSFLAGS :=
endif

# ── Object files ──────────────────────────────────────────────────────────────
KERNEL_OBJS := kernel.o       \
               test_module_stub.o \
               $(BOCHS_OBJ)   \
               bochs_cstubs.o \
               $(TCC_OBJ)     \
               $(TCC_EXTRA)

# =============================================================================
# Phony targets
# =============================================================================
.PHONY: all clean clean_tcc fat fatcp tcc_download tcc_build help check_m32

all: $(KERNEL_ELF)

help:
	@echo "Usage:"
	@echo "  make              Build kernel with TCC stub (default, no download)"
	@echo "  make TCC=1        Build with TCC glue (auto-downloads TCC 0.9.27)"
	@echo "  make fat TCC=1    Copy libtcc.so into \$(DISK_IMG) via mtools"
	@echo "  make all TCC=1    Build kernel + copy libtcc.so to disk"
	@echo "  make clean        Remove build artifacts"
	@echo "  make clean_tcc    Also remove TCC source tree and tarball"
	@echo ""
	@echo "Prerequisites (Ubuntu/Debian):"
	@echo "  sudo apt install gcc g++ gcc-multilib g++-multilib binutils nasm mtools wget"

# Sanity-check: ensure -m32 works (needs gcc-multilib / g++-multilib).
check_m32:
	@printf 'int main(){return 0;}' | \
	  $(CXX) $(M32) -ffreestanding -nostdlib -x c++ - -o /dev/null 2>/dev/null || \
	  { echo ""; \
	    echo "ERROR: $(CXX) cannot produce 32-bit (-m32) output."; \
	    echo "Fix with:  sudo apt install gcc-multilib g++-multilib"; \
	    echo ""; \
	    exit 1; }
	@echo "[OK]  $(CXX) -m32 works"

# =============================================================================
# Kernel link
# =============================================================================
$(KERNEL_ELF): $(KERNEL_OBJS)
	$(LD) $(LDFLAGS) -o $@ $^
	@echo "[LD]  $@"

# =============================================================================
# Kernel compilation
# =============================================================================
kernel.o: kernel.cpp tcc_glue.h | check_m32
	$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "[CXX] $< -> $@"

# =============================================================================
# Bochs objects
# =============================================================================
bochs_glue.o: bochs_glue.cpp | check_m32
	$(CXX) $(CXXFLAGS) $(BOCHSFLAGS) -c $< -o $@
	@echo "[CXX] $< -> $@  (BOCHS=1)"

bochs_stub.o: bochs_stub.cpp | check_m32
	$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "[CXX] $< -> $@  (BOCHS=0 stub)"

bochs_cstubs.o: bochs_cstubs.c | check_m32
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "[CC]  $< -> $@"

# =============================================================================
# test_module stub
# =============================================================================
test_module_stub.o: test_module_stub.cpp test_module.h | check_m32
	$(CXX) $(CXXFLAGS) -c test_module_stub.cpp -o $@
	@echo "[CXX] test_module_stub.cpp -> $@"

# =============================================================================
# TCC objects
# =============================================================================

# Real glue — libtcc.so is needed at *runtime* on FAT32, not at link time.
tcc_glue.o: tcc_glue.cpp tcc_glue.h | tcc_build check_m32
	$(CXX) $(CXXFLAGS) $(TCCFLAGS) -c tcc_glue.cpp -o $@
	@echo "[CXX] tcc_glue.cpp -> $@  (TCC=1)"

# Embed libtcc.so as a raw binary section so tcc_glue.cpp can access it via
# the linker symbols libtcc_start / libtcc_end at runtime.
# objcopy --input-target binary names the symbols after the filename:
#   _binary_<name>_start / _binary_<name>_end / _binary_<name>_size
# We rename them to the plain names expected by tcc_glue.cpp.
libtcc_embed.o: $(LIBTCC_SO)
	@# cd into the SO's directory so objcopy sees only "libtcc.so" (no path
	@# separators), ensuring the generated symbols are named:
	@#   _binary_libtcc_so_start / _binary_libtcc_so_end / _binary_libtcc_so_size
	@# rather than _binary_tcc_build_i386_libtcc_so_start etc.
	cd $(TCC_BUILD_DIR) && $(OBJCOPY) \
	  --input-target  binary \
	  --output-target elf32-i386 \
	  --binary-architecture i386 \
	  --rename-section .data=.rodata.libtcc,alloc,load,readonly,data,contents \
	  libtcc.so $(CURDIR)/$@
	$(OBJCOPY) \
	  --redefine-sym _binary_libtcc_so_start=libtcc_start \
	  --redefine-sym _binary_libtcc_so_end=libtcc_end     \
	  --redefine-sym _binary_libtcc_so_size=libtcc_size   \
	  $@ $@
	@# Suppress "missing .note.GNU-stack implies executable stack" linker warning.
	$(OBJCOPY) --add-section .note.GNU-stack=/dev/null $@ $@
	@echo "[EMB] $(LIBTCC_SO) -> $@  (libtcc_start/libtcc_end defined)"

# No-op stub — used when TCC=0.
tcc_stub.o: tcc_stub.cpp tcc_glue.h | check_m32
	$(CXX) $(CXXFLAGS) -c tcc_stub.cpp -o $@
	@echo "[CXX] tcc_stub.cpp -> $@  (TCC=0 stub)"

# =============================================================================
# TCC 0.9.27 — auto-download and build libtcc.so (i386, stripped).
# Only runs when TCC=1 and $(LIBTCC_SO) doesn't exist yet.
# =============================================================================

tcc_download: $(TCC_TARBALL)

$(TCC_TARBALL):
	@echo "[GET] Downloading TCC $(TCC_VERSION)..."
	wget -q --show-progress -O $(TCC_TARBALL) $(TCC_URL) || \
	  { rm -f $(TCC_TARBALL); \
	    echo "wget failed — check your internet connection"; exit 1; }

tcc_build: $(LIBTCC_SO)

$(LIBTCC_SO): $(TCC_TARBALL)
	@echo "[TAR] Unpacking $(TCC_TARBALL)..."
	tar -xjf $(TCC_TARBALL)
	@echo "[CFG] Configuring TCC for i386 ELF output..."
	cd $(TCC_SRC_DIR) && \
	  ./configure \
	    --prefix=/tmp/tcc-i386-install \
	    --cpu=i386                      \
	    --enable-static                 \
	    --disable-nls                   \
	    --extra-cflags="-m32 -O2"       \
	    --extra-ldflags="-m32"
	@echo "[BLD] Building libtcc.so (i386, ~30 s)..."
	$(MAKE) -C $(TCC_SRC_DIR) libtcc.so
	mkdir -p $(TCC_BUILD_DIR)
	cp $(TCC_SRC_DIR)/libtcc.so $(LIBTCC_SO)
	$(STRIP) --strip-unneeded $(LIBTCC_SO)
	@echo "[OK]  libtcc.so ready: $$(du -sh $(LIBTCC_SO) | cut -f1)"
	@echo "      Copy to FAT32 disk:  make fat"

# =============================================================================
# Copy libtcc.so into the FAT32 disk image so the kernel can load it.
# Requires mtools (mcopy) and a valid FAT32 image at $(DISK_IMG).
# =============================================================================
# Automatically build the disk image if it's missing, then copy libtcc.so
fat: $(LIBTCC_SO)
	@if [ ! -f "$(DISK_IMG)" ]; then \
		echo "[IMG] $(DISK_IMG) not found. Creating a fresh 40MB FAT32 image..."; \
		dd if=/dev/zero of=$(DISK_IMG) bs=1M count=40 2>/dev/null; \
		mkfs.vfat -F 32 $(DISK_IMG) >/dev/null; \
	fi
	@echo "[FAT] Copying $(LIBTCC_SO) -> $(DISK_IMG)::libtcc.so"
	mcopy -i $(DISK_IMG) -o $(LIBTCC_SO) ::libtcc.so
	@echo "[FAT] Done. Boot the kernel and run: tcc hello.c"

# Convenience: copy any file onto the disk (make fatcp SRC=hello.c)
fatcp:
	@test -n "$(SRC)" || { echo "Usage: make fatcp SRC=<file>"; exit 1; }
	@test -f "$(DISK_IMG)" || \
	  { echo "ERROR: $(DISK_IMG) not found. Set DISK_IMG=<path>."; exit 1; }
	mcopy -i $(DISK_IMG) -o $(SRC) ::$(notdir $(SRC))
	@echo "[FAT] Copied $(SRC) -> $(DISK_IMG)::$(notdir $(SRC))"
# ── ISO Output Configuration ──────────────────────────────────────────────────
ISO_OUT   := kernel.iso
ISO_DIR   := iso_root

# Generates a bootable GRUB-based ISO containing your kernel and libtcc.so
iso: $(KERNEL_ELF) $(LIBTCC_SO)
	@echo "[ISO] Setting up ISO staging directory..."
	@mkdir -p $(ISO_DIR)/boot/grub
	
	@# 1. Copy the core kernel binary into the boot directory
	@cp $(KERNEL_ELF) $(ISO_DIR)/boot/$(KERNEL_ELF)
	
	@# 2. Copy libtcc.so into the root of the ISO image so your kernel can find it
	@if [ -f "$(LIBTCC_SO)" ]; then \
		cp $(LIBTCC_SO) $(ISO_DIR)/libtcc.so; \
		echo "[ISO] Embedded $(LIBTCC_SO) -> /libtcc.so"; \
	fi
	
	@# 3. Dynamically generate a minimal grub.cfg configuration file
	@echo "set default=0"                  > $(ISO_DIR)/boot/grub/grub.cfg
	@echo "set timeout=0"                 >> $(ISO_DIR)/boot/grub/grub.cfg
	@echo "menuentry \"My Freestanding Kernel\" {" >> $(ISO_DIR)/boot/grub/grub.cfg
	@echo "    multiboot /boot/$(KERNEL_ELF)"   >> $(ISO_DIR)/boot/grub/grub.cfg
	@echo "    boot"                      >> $(ISO_DIR)/boot/grub/grub.cfg
	@echo "}"                             >> $(ISO_DIR)/boot/grub/grub.cfg
	
	@# 4. Compile everything into a bootable El Torito ISO
	@echo "[ISO] Mastering $(ISO_OUT) via grub-mkrescue..."
	@grub-mkrescue -o $(ISO_OUT) $(ISO_DIR) 2>/dev/null || \
	  mkisofs -R -b boot/grub/stage2_eltorito -no-emul-boot -boot-load-size 4 -boot-info-table -o $(ISO_OUT) $(ISO_DIR)
	
	@# 5. Clean up the temporary staging directory
	@rm -rf $(ISO_DIR)
	@echo "[OK]  ISO generation complete: $(ISO_OUT)"
# =============================================================================
# Clean
# =============================================================================
clean:
	rm -f $(KERNEL_ELF) $(KERNEL_OBJS) $(ISO_OUT)
	rm -rf $(ISO_DIR)
	rm -f kernel.o tcc_glue.o tcc_stub.o libtcc_embed.o test_module_stub.o \
	      bochs_glue.o bochs_stub.o bochs_cstubs.o
	@echo "[CLN] Build artifacts and ISO removed."

clean_tcc: clean
	rm -rf $(TCC_SRC_DIR) $(TCC_BUILD_DIR) $(TCC_TARBALL)
	@echo "[CLN] TCC source, build dir, and tarball removed."
