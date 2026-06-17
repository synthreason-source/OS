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

# ── Bochs ────────────────────────────────────────────────────
# BOCHS_VERSION is the target emulator version for download when the
# offline bundle is absent. The offline bundle always ships as bochs-2.7/
# (the version the prebuilt libs were built from); BOCHS_DIR always
# points there so existing prebuilt libs are found immediately.
# If bochs-2.7/ is missing the build downloads BOCHS_VERSION instead.
BOCHS_VERSION   := 2.0.2
BOCHS_DIR       := bochs-2.0.2
BOCHS_ARCHIVE   := bochs-$(BOCHS_VERSION).tar.gz
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
	rm -rf *.o main.iso iso hello hello_blob.o tcc_tool libtcc_glue.so i386-libtcc-kern.a

# distclean removes build artifacts and the disk image, but KEEPS the
# prebuilt bochs-2.7/ tree and the local TCC build.
distclean: clean
	# NOTE: bochs-2.7/ is intentionally NOT removed (offline bundle).
	# NOTE: tcc-local/ and tcc-src/ are also kept so `make cc` works
	#       without re-downloading. Remove them by hand if needed:
	#         rm -rf tcc-local tcc-src tcc-mob.tar.gz
	rm -rf $(BOCHS_ARCHIVE) ramdisk.o $(DISK_IMG)

# Remove the local TCC build completely (forces re-download on next setup-tcc).
tcc-clean:
	rm -rf $(TCC_LOCAL) $(TCC_SRC_DIR) $(TCC_ARCHIVE)

.PHONY: all clean distclean tcc-clean iso test_main run-test cc tcc setup-tcc download-tcc

# ============================================================
#  TCC glue — host-side C compiler for guest ELFs
# ------------------------------------------------------------
#  Mirrors the bochs_glue pattern: tcc_glue.cpp wraps libtcc
#  into a CLI tool (tcc_tool) and a shared library
#  (libtcc_glue.so).  The kernel links tcc_stub.cpp (no-ops)
#  so the kernel binary does not depend on TCC at run time.
#
#  TCC is built from source automatically — no apt required.
#  Run once before first use:
#    make setup-tcc          # download + build TCC into tcc-local/
#
#  Then compile guest programs normally:
#    make cc SRC=prog.c      # OUT defaults to stem of SRC
#    make cc SRC=prog.c OUT=prog
#
#  The compiled 32-bit ELF is written to disk.img.  Boot the OS
#  and type the ELF name in a terminal to run it.
#
#  Under the hood:
#    1. i386-tcc -c prog.c → prog.o  (relocatable 32-bit i386 object)
#    2. ld -m elf_i386 -T tcc_guest.ld → ELF32 (code at 0x08002000,
#       safely past the Bochs slot GDT/IDT/stub injection zone)
#    3. mtools mcopy prog → disk.img::/prog
# ============================================================

# ── Local TCC build paths ────────────────────────────────────────────────────
# TCC is built from source into tcc-local/ so we get:
#   tcc-local/bin/i386-tcc   — cross-compiler targeting i386
#   tcc-local/lib/libtcc.a   — embedded-compiler library
#   tcc-local/include/libtcc.h
#
# TCC source: GitHub mirror of the official mob (development) branch.
TCC_LOCAL     := tcc-local
TCC_SRC_DIR   := tcc-src
TCC_REPO      := https://github.com/TinyCC/tinycc/archive/refs/heads/mob.tar.gz
TCC_ARCHIVE   := tcc-mob.tar.gz
TCC_I386      := $(TCC_LOCAL)/bin/i386-tcc
TCC_LIB       := $(TCC_LOCAL)/lib/libtcc.a
TCC_INC       := $(TCC_LOCAL)/include/libtcc.h

# ── Auto-detect: use system TCC/libtcc if present, else fall back to local ──
# If the local build exists it takes priority (consistent cross-compiler).
# The shell function runs at parse time so it only queries what is installed.
TCC_TOOL   := tcc_tool
TCC_SO     := libtcc_glue.so

# Include / link flags — prefer local build, then system.
TCC_IFLAGS := $(shell \
    if [ -f $(TCC_INC) ]; then echo "-I$(TCC_LOCAL)/include"; \
    elif pkg-config --exists libtcc 2>/dev/null; then pkg-config --cflags libtcc; \
    fi)
TCC_LIBS   := $(shell \
    if [ -f $(TCC_LIB) ]; then echo "$(TCC_LOCAL)/lib/libtcc.a"; \
    elif pkg-config --exists libtcc 2>/dev/null; then pkg-config --libs libtcc; \
    else echo "-ltcc"; \
    fi)
TCC_CFLAGS := -O2 -Wall -std=c++17 $(TCC_IFLAGS)

# ── setup-tcc / download-tcc ─────────────────────────────────────────────────
# Downloads TCC source from GitHub and builds:
#   • i386-tcc  (cross-compiler: host=x86-64, target=i386)
#   • libtcc.a  (embedded compiler library, position-independent)
#   • libtcc.h  (API header)
#
# Requires on the build host: gcc make (already needed for the kernel build).
# binutils-multiarch is needed for ld -m elf_i386; install it once:
#   sudo apt install binutils-multiarch
#
# Everything else is self-contained in tcc-local/.

$(TCC_ARCHIVE):
	@echo ">>> Downloading TCC source (mob branch) from GitHub ..."
	wget -O $@ "$(TCC_REPO)" || curl -L -o $@ "$(TCC_REPO)"
	@echo ">>> Download complete: $@"


$(TCC_SRC_DIR)/.extracted: $(TCC_ARCHIVE)
	@echo ">>> Extracting TCC source ..."
	mkdir -p $(TCC_SRC_DIR)
	tar -xzf $(TCC_ARCHIVE) --strip-components=1 -C $(TCC_SRC_DIR)
	touch $@
	sed -i 's/tcc_error_noabort("'"'"'%s'"'"' defined twice", name);/\/\* ignore \*\//' $(TCC_SRC_DIR)/tccelf.c
	touch $@

# Build i386-tcc cross-compiler + libtcc into tcc-local/.
# Flags used:
#   --prefix        install into tcc-local/ (no root needed)
#   --enable-cross  build cross-compilers for all TCC targets (includes i386-tcc)
#   --extra-cflags  -fPIC so libtcc.a is position-independent and linkable into .so
$(TCC_I386) $(TCC_LIB) $(TCC_INC) &: $(TCC_SRC_DIR)/.extracted
	@echo ">>> Configuring TCC for cross-compilation (target: i386) ..."
	cd $(TCC_SRC_DIR) && ./configure \
	    --prefix="$(CURDIR)/$(TCC_LOCAL)" \
	    --enable-cross \
	    --extra-cflags="-fPIC -O2"
	@echo ">>> Building TCC ..."
	$(MAKE) -C $(TCC_SRC_DIR)
	@echo ">>> Installing TCC into $(TCC_LOCAL)/ ..."
	$(MAKE) -C $(TCC_SRC_DIR) install
	@echo ">>> TCC ready."
	@echo "    cross-compiler : $(TCC_I386)"
	@echo "    libtcc         : $(TCC_LIB)"
	@echo "    header         : $(TCC_INC)"

# Friendly aliases.
setup-tcc download-tcc: $(TCC_I386) $(TCC_KERN_LIB)
	@echo ">>> setup-tcc complete."
	@echo "    host cross-compiler : $(TCC_I386)"
	@echo "    kernel TCC library  : $(TCC_KERN_LIB)"
	@echo "    Now run: make BOCHS=1  to rebuild the kernel with in-kernel TCC."
	@echo "    Inside the OS:  cc hello_tcc.c"

# ── Host shared library ──────────────────────────────────────────────────────
# Note: libtcc.a built above is -fPIC, so we can link it into the .so.
$(TCC_SO): tcc_glue.cpp $(TCC_LIB)
	@echo ">>> Building $(TCC_SO) ..."
	g++ $(TCC_CFLAGS) -fPIC -shared \
	    -o $@ $< \
	    $(TCC_LIBS) -ldl
	@echo ">>> $(TCC_SO) ready."

# ── Standalone CLI tool ───────────────────────────────────────────────────────
$(TCC_TOOL): tcc_glue.cpp $(TCC_LIB)
	@echo ">>> Building $(TCC_TOOL) ..."
	g++ $(TCC_CFLAGS) \
	    -DHAVE_LIBTCC \
	    -o $@ $< \
	    $(TCC_LIBS) -ldl
	@echo ">>> $(TCC_TOOL) ready."

# ── cc / tcc targets ────────────────────────────────────────────────────────
# Compile a C source file → 32-bit ELF → inject into disk.img.
#
#   make cc SRC=foo.c
#   make cc SRC=foo.c OUT=foo
#   make tcc SRC=foo.c            (alias)
#
# SRC may be:
#   - A host-filesystem path  (e.g. hello_tcc.c)
#   - A filename that already exists on disk.img (mtools reads it out)
#
# The ELF is linked with tcc_guest.ld: code lands at 0x08002000,
# safely past the Bochs slab GDT/IDT/stub injection zone.

ifndef SRC
SRC :=
endif
ifndef OUT
OUT :=
endif

# Ensure i386-tcc is on PATH from the local build.
export PATH := $(CURDIR)/$(TCC_LOCAL)/bin:$(PATH)

cc tcc: $(TCC_TOOL) $(DISK_IMG) tcc_guest.ld
	@if [ ! -x "$(TCC_I386)" ] && ! command -v i386-tcc >/dev/null 2>&1; then \
	    echo ""; \
	    echo "ERROR: i386-tcc not found."; \
	    echo "Run  make setup-tcc  to download and build TCC automatically,"; \
	    echo "then retry:  make cc SRC=$(SRC)"; \
	    echo ""; \
	    exit 1; \
	fi
ifndef SRC
	@echo "Usage: make cc SRC=<file.c> [OUT=<name>]"
	@echo "  Compiles SRC to a 32-bit ELF and writes it to $(DISK_IMG)."
	@exit 1
endif
	@echo ">>> Compiling $(SRC) → $(or $(OUT),$(basename $(notdir $(SRC)))) in $(DISK_IMG) ..."
	./$(TCC_TOOL) "$(DISK_IMG)" "$(SRC)" "$(OUT)" "tcc_guest.ld"
	@echo ">>> Done. Boot the OS and type '$(or $(OUT),$(basename $(notdir $(SRC))))' to run it."

# ============================================================
#  Bochs CPU/FPU/cpudb/memory static libraries
# ------------------------------------------------------------
#  OFFLINE BUNDLE: this tree ships with bochs-2.7/ already
#  configured and with the four static libs prebuilt
#  (cpu/libcpu.a, cpu/fpu/libfpu.a, memory/libmemory.a). When those libs are present "make"
#  uses them directly and performs NO download / configure.
#
#  If the prebuilt libs are absent, the rule falls back to the
#  original behaviour: download the tarball, extract, configure
#  --with-nogui, and build the four libs.
# ============================================================
# Download rule for the target version (only runs if bochs-2.7.tar.gz absent).
$(BOCHS_ARCHIVE):
	wget -O $@ "$(BOCHS_URL)" || curl -L -o $@ "$(BOCHS_URL)"

# libcpu.a — three-stage bootstrap:
#   1. If already built/extracted: done.
#   2. If bochs-2.7.tar.gz is present (offline bundle): extract it.
#   3. Otherwise: download BOCHS_VERSION, extract, configure, build.
$(BOCHS_CPU_LIB):
	@if [ -f "$(BOCHS_CPU_LIB)" ]; then \
	    echo ">>> Using prebuilt Bochs libs in $(BOCHS_DIR)/"; \
	elif [ -f "bochs-2.7.tar.gz" ]; then \
	    echo ">>> Extracting offline bundle bochs-2.7.tar.gz..."; \
	    tar -xzf bochs-2.7.tar.gz; \
	    cp instrument_stub.h $(BOCHS_DIR)/instrument.h; \
	    if [ ! -f "$(BOCHS_CPU_LIB)" ]; then \
	        echo ">>> Building Bochs libs from extracted bundle..."; \
	        cd $(BOCHS_DIR) && ./configure \
	            --enable-cpu-level=6 --enable-fpu --with-nogui \
	            --host=i686-linux-gnu --enable-x86-64 \
	            CXXFLAGS="-O2 -m32 -fno-stack-protector -fno-pie" \
	            CFLAGS="-O2 -m32 -fno-stack-protector -fno-pie" && cd ..; \
	        $(MAKE) -C $(BOCHS_DIR)/cpu; \
	        $(MAKE) -C $(BOCHS_DIR)/cpu/fpu; \
	        $(MAKE) -C $(BOCHS_DIR)/cpu/cpudb; \
	        $(MAKE) -C $(BOCHS_DIR)/memory; \
	    fi \
	else \
	    echo ">>> Downloading Bochs $(BOCHS_VERSION) (target version)..."; \
	    wget -O "$(BOCHS_ARCHIVE)" "$(BOCHS_URL)" || curl -L -o "$(BOCHS_ARCHIVE)" "$(BOCHS_URL)"; \
	    tar -xzf "$(BOCHS_ARCHIVE)"; \
	    cp instrument_stub.h $(BOCHS_DIR)/instrument.h; \
	    cd $(BOCHS_DIR) && ./configure \
	        --enable-cpu-level=6 --enable-fpu --with-nogui \
	        CXXFLAGS="-O2 -m32 -fno-stack-protector -fno-pie" \
	        CFLAGS="-O2 -m32 -fno-stack-protector -fno-pie" && cd ..; \
	    $(MAKE) -C $(BOCHS_DIR)/cpu; \
	    $(MAKE) -C $(BOCHS_DIR)/cpu/fpu; \
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



BOCHS_OBJ    := bochs_glue.o bochs_infra.o bochs_paramtree.o bochs_pc_system.o bochs_cstubs.o setjmp.o test_module.o tcc_kernel.o
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

# ── i386-libtcc-kern.a — TCC compiled to target i386, linked into the kernel ──
# Built by setup-tcc from TCC's libtcc.c with:
#   -DTCC_TARGET_I386 -DONE_SOURCE=1 -DCONFIG_TCC_SEMLOCK=0
# so tcc_kernel.cpp can call tcc_new/tcc_compile_string/tcc_output_file in-kernel.
TCC_KERN_LIB := i386-libtcc-kern.a

$(TCC_KERN_LIB): $(TCC_I386)
	@echo ">>> Building i386-targeting libtcc for kernel ..."
	cd $(TCC_SRC_DIR) && gcc -m32 -c libtcc.c \
	    -DTCC_TARGET_I386 -DONE_SOURCE=1 -DCONFIG_TCC_SEMLOCK=0 \
	    "-DCONFIG_TCC_CROSSPREFIX=\"i386-\"" \
	    "-DCONFIG_TCCDIR=\"/tcc\"" \
	    "-DCONFIG_TCC_SYSROOTDIR=\"\"" \
	    "-DCONFIG_TCC_LIBPATHS=\"{B}\"" \
	    "-DTCC_LIBTCC1=\"\"" \
	    "-DCONFIG_TCC_CRTPREFIX=\"{B}\"" \
	    '-DCONFIG_TCC_ELFINTERP="/lib/ld-linux.so.2"' \
	    -DTCC_IS_NATIVE=0 \
	    -I. -O2 -w -fno-stack-protector -U_FORTIFY_SOURCE -fno-builtin \
	    -o i386-libtcc-kern.o
	ar rcs $(CURDIR)/$(TCC_KERN_LIB) $(TCC_SRC_DIR)/i386-libtcc-kern.o
	@echo ">>> $(TCC_KERN_LIB) ready."

# tcc_kernel.o — real in-kernel TCC glue (replaces tcc_stub.o).
# Compiled freestanding i386; provides all POSIX shims libtcc.a needs.
# Depends on $(TCC_KERN_LIB) existing so libtcc.h is available.
tcc_kernel.o: tcc_kernel.cpp $(TCC_KERN_LIB)
	g++ -m32 -O2 -ffreestanding -fno-pie -fno-pic -fno-exceptions -fno-rtti \
	    -fno-stack-protector -std=c++17 \
	    -I$(TCC_SRC_DIR) \
	    -c tcc_kernel.cpp -o tcc_kernel.o

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
$(MULTIBOOT): boot.o kernel.o ramdisk.o hello_blob.o test_module.o $(BOCHS_OBJ) $(TCC_KERN_LIB) $(BOCHS_DEP)
	mkdir -p iso/boot
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(MULTIBOOT)              \
	    -Wl,--start-group             \
	    boot.o kernel.o ramdisk.o hello_blob.o \
	    $(BOCHS_OBJ)                  \
	    $(TCC_KERN_LIB)               \
	    $(BOCHS_LIBS)                 \
	    -lgcc $(LIBGCC_EH)            \
	    -Wl,--end-group               \
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
test_main: boot.o test_main.o $(BOCHS_OBJ) $(TCC_KERN_LIB) $(BOCHS_DEP)
	mkdir -p iso/boot/grub
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(TEST_ELF) \
	    -Wl,--start-group             \
	    boot.o test_main.o            \
	    $(BOCHS_OBJ)                  \
	    $(TCC_KERN_LIB)               \
	    $(BOCHS_LIBS)                 \
	    -lgcc $(LIBGCC_EH)            \
	    -Wl,--end-group               \
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