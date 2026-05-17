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
	printf '%s\n'                              \
	    'set timeout=0'                         \
	    'set default=0'                         \
	    'terminal_input console'                \
	    'terminal_output console'               \
	    'menuentry "RTOS++" {'                  \
	    '    multiboot /boot/main.elf'          \
	    '    boot'                              \
	    '}'                                     \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue -o main.iso iso
	@echo ">>> ISO ready: main.iso"


clean:
	rm -rf *.o main.iso iso hello hello_blob.o

# distclean removes build artifacts and the disk image, but KEEPS the
# prebuilt bochs-2.7/ tree (see note in recipe).
distclean: clean
	# NOTE: the prebuilt bochs-2.7/ tree is intentionally NOT removed,
	#       so the offline bundle stays buildable. Remove it by hand to
	#       force a fresh download + configure on the next build.
	rm -rf $(BOCHS_ARCHIVE) ramdisk.o $(DISK_IMG)

.PHONY: all clean distclean iso test_main run-test

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
$(MULTIBOOT): boot.o kernel.o ramdisk.o hello_blob.o test_module.o $(BOCHS_OBJ) $(BOCHS_DEP)
	mkdir -p iso/boot
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(MULTIBOOT)              \
	    boot.o kernel.o ramdisk.o hello_blob.o $(BOCHS_OBJ) \
	    $(BOCHS_LIBS)                \
	    -lgcc $(LIBGCC_EH)           \
	    -Wl,--allow-multiple-definition

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
	    '    boot'                        \
	    '}'                               \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue -o $(MAIN) iso
	@echo ">>> ISO ready: $(MAIN)"

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