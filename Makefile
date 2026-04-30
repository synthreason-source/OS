# ============================================================
#  Makefile – Bare-metal OS with Bochs CPU emulation + BusyBox
# ============================================================

ISODIR   := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN     := main.iso

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

# ============================================================
#  Top-level targets
# ============================================================
all: $(MAIN)

run: $(MAIN)
	qemu-system-i386 -cdrom $(MAIN) -m 256M -vga std

clean:
	rm -rf *.o main.iso iso

distclean: clean
	rm -rf $(BOCHS_DIR) $(BOCHS_ARCHIVE) $(BUSYBOX_BIN) ramdisk.o

.PHONY: all run clean distclean

# ============================================================
#  Bochs: download -> extract -> configure -> build cpu libs
# ============================================================
$(BOCHS_ARCHIVE):
	wget -O $@ "$(BOCHS_URL)" || curl -L -o $@ "$(BOCHS_URL)"

$(BOCHS_DIR)/.extracted: $(BOCHS_ARCHIVE)
	tar -xzf $(BOCHS_ARCHIVE)
	touch $@

# We only need the CPU / FPU / cpudb / memory static libs.
$(BOCHS_CPU_LIB): $(BOCHS_DIR)/.extracted
	cd $(BOCHS_DIR) && ./configure          \
	    --enable-cpu-level=6                \
	    --enable-fpu                         \
	    --disable-mmx                        \
	    --disable-sse                        \
	    --disable-avx                        \
	    --disable-x86-64                     \
	    --disable-debugger                   \
	    --with-nogui                         \
	    --disable-gui                        \
	    CXXFLAGS="-O2 -m32 -fno-stack-protector" \
	    CFLAGS="-O2 -m32 -fno-stack-protector"
	$(MAKE) -C $(BOCHS_DIR)/cpu
	$(MAKE) -C $(BOCHS_DIR)/cpu/fpu
	$(MAKE) -C $(BOCHS_DIR)/cpu/cpudb
	$(MAKE) -C $(BOCHS_DIR)/memory

# Bochs instrument stub header (required by bochs_glue.cpp)
$(BOCHS_DIR)/instrument.h: $(BOCHS_CPU_LIB)
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

# ============================================================
#  Bochs CPU emulation: off by default (set BOCHS=1 to enable)
#  Without BOCHS=1, bochs_stub.cpp is used (all bochs functions
#  are no-ops) and the Bochs libraries are not required.
# ============================================================
BOCHS ?= 0

ifeq ($(BOCHS),1)
BOCHS_OBJ    := bochs_glue.o
BOCHS_LIBS   := $(BOCHS_DIR)/cpu/libcpu.a \
                $(BOCHS_DIR)/cpu/fpu/libfpu.a \
                $(BOCHS_DIR)/cpu/cpudb/libcpudb.a \
                $(BOCHS_DIR)/memory/libmemory.a
BOCHS_IFLAGS := -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu
BOCHS_DEP    := $(BOCHS_CPU_LIB)
BOCHS_CDEF   := -DBOCHS_ENABLED=1
else
BOCHS_OBJ    := bochs_stub.o
BOCHS_LIBS   :=
BOCHS_IFLAGS :=
BOCHS_DEP    :=
BOCHS_CDEF   :=
endif

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

# ============================================================
#  Link
# ============================================================
$(MULTIBOOT): boot.o kernel.o ramdisk.o $(BOCHS_OBJ) $(BOCHS_DEP)
	mkdir -p iso/boot
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(MULTIBOOT)              \
	    boot.o kernel.o ramdisk.o $(BOCHS_OBJ) \
	    $(BOCHS_LIBS)                \
	    -lgcc

# ============================================================
#  ISO image via GRUB
# ============================================================
$(MAIN): $(MULTIBOOT)
	mkdir -p iso/boot/grub
	printf '%s\n'                         \
	    'set timeout=0'                   \
	    'set default=0'                   \
	    'menuentry "RTOS++" {'            \
	    '    multiboot /boot/main.elf'    \
	    '}'                               \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue -o $(MAIN) iso
	@echo ">>> ISO ready: $(MAIN)"
