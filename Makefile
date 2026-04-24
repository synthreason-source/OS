ISODIR := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN := main.iso
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra -std=c++17 -fno-exceptions -fno-rtti -m32

# BusyBox 32-bit binary URL and local filename
BUSYBOX_URL := https://busybox.net/downloads/binaries/1.35.0-i686-linux-musl/busybox
BUSYBOX_BIN := busybox

# Bochs
# Replace BOCHS_URL/BOCHS_ARCHIVE section at top of Makefile with:
# =============================================================================
# BOCHS - BUILD PROPERLY THEN EXTRACT CPU LIBRARY
# =============================================================================

BOCHS_VERSION    := 2.7
BOCHS_DIR        := bochs-$(BOCHS_VERSION)
BOCHS_GH_ARCHIVE := bochs-$(BOCHS_VERSION).tar.gz
BOCHS_GH_URL     := https://downloads.sourceforge.net/project/bochs/bochs/$(BOCHS_VERSION)/bochs-$(BOCHS_VERSION).tar.gz
BOCHS_CPU_LIB    := $(BOCHS_DIR)/cpu/.libs/libcpu.a
BOCHS_INCLUDES   := $(BOCHS_DIR)


$(BOCHS_DIR)/.extracted: $(BOCHS_GH_ARCHIVE)
	tar -xzf $(BOCHS_GH_ARCHIVE)
	@test -d $(BOCHS_DIR) || { echo "Extract failed"; exit 1; }
	touch $(BOCHS_DIR)/.extracted

bochs-patch: $(BOCHS_DIR)/.patched

$(BOCHS_DIR)/.patched: $(BOCHS_DIR)/.extracted
	@echo "No manual patching needed - using configure"
	touch $(BOCHS_DIR)/.patched

bochs-build: $(BOCHS_CPU_LIB)

$(BOCHS_CPU_LIB): $(BOCHS_DIR)/.extracted
	@echo "Configuring Bochs (CPU only, no GUI)..."
	cd $(BOCHS_DIR) && ./configure \
	    --enable-cpu-level=6 \
	    --disable-x86-64 \
	    --enable-fpu \
	    --disable-mmx \
	    --disable-sse \
	    --disable-vmx \
	    --disable-svm \
	    --disable-avx \
	    --disable-evex \
	    --disable-debugger \
	    --disable-disasm \
	    --disable-gdb-stub \
	    --disable-docbook \
	    --disable-plugins \
	    --without-x \
	    --without-x11 \
	    --without-wx \
	    --without-sdl \
	    --without-sdl2 \
	    --without-nogui \
	    --without-term \
	    --without-rfb \
	    --without-vnc \
	    --without-svga \
		--enable-cpu-level=6 \
		--enable-fpu \
		--enable-instrumentation="instrument/stubs" \
		--disable-mmx --disable-sse --disable-avx --disable-evex \
		--disable-x86-64 --disable-vmx --disable-svm \
		--disable-debugger --disable-disasm --disable-gdb-stub \
		--disable-docbook --disable-plugins \
		--without-x --without-x11 --without-wx --without-sdl --without-sdl2 \
		--without-nogui --without-term --without-rfb --without-vnc --without-svga \
	    CXXFLAGS="-O2 -m32 -fno-exceptions -fno-rtti" \
	    CFLAGS="-O2 -m32"
	@echo "Building Bochs CPU library..."
	cd $(BOCHS_DIR)/cpu && $(MAKE)
	@echo "Bochs CPU library built: $(BOCHS_CPU_LIB)"

BOCHS_DEFINES := \
    -DBOCHS_STANDALONE_CPU=1 \
    -DBX_CPU_LEVEL=6 \
    -DBX_SUPPORT_X86_64=0 \
    -DBX_SUPPORT_FPU=0 \
    -DBX_SUPPORT_SSE=0 \
    -DBX_SUPPORT_VMX=0 \
	-DBX_SUPPORT_MMX=0 \
    -DBX_SUPPORT_SVM=0 \
    -DBX_SUPPORT_MONITOR_MWAIT=0 \
    -DBX_SUPPORT_APIC=0 \
    -DBX_SUPPORT_PAGING=0 \
    -DBX_USE_CPU_SMF=0 \
    -DBX_DEBUGGER=0 \
    -DBX_GDBSTUB=0 \
    -DBX_INSTRUMENTATION=1 \
    -DBX_SMP_PROCESSORS=1 \
    -DPACKAGE_VERSION=\"$(BOCHS_VERSION)\"

BOCHS_CXXFLAGS := $(CXXFLAGS) $(BOCHS_DEFINES) \
    -I$(BOCHS_DIR) \
    -I$(BOCHS_DIR)/cpu \
    -Wno-sign-compare \
    -Wno-unused-parameter \
    -Wno-deprecated-declarations \
    -Wno-narrowing \
    -Wno-extra

BOCHS_CPU_SRCS := \
    $(BOCHS_DIR)/cpu/access.cc \
    $(BOCHS_DIR)/cpu/arith16.cc \
    $(BOCHS_DIR)/cpu/arith32.cc \
    $(BOCHS_DIR)/cpu/arith8.cc \
    $(BOCHS_DIR)/cpu/bit.cc \
    $(BOCHS_DIR)/cpu/branch.cc \
    $(BOCHS_DIR)/cpu/call_far.cc \
    $(BOCHS_DIR)/cpu/cpu.cc \
    $(BOCHS_DIR)/cpu/ctrl_xfer16.cc \
    $(BOCHS_DIR)/cpu/ctrl_xfer32.cc \
    $(BOCHS_DIR)/cpu/data_xfer16.cc \
    $(BOCHS_DIR)/cpu/data_xfer32.cc \
    $(BOCHS_DIR)/cpu/data_xfer8.cc \
    $(BOCHS_DIR)/cpu/div.cc \
    $(BOCHS_DIR)/cpu/exception.cc \
    $(BOCHS_DIR)/cpu/fetchdecode.cc \
    $(BOCHS_DIR)/cpu/flag_ctrl.cc \
    $(BOCHS_DIR)/cpu/init.cc \
    $(BOCHS_DIR)/cpu/io.cc \
    $(BOCHS_DIR)/cpu/lazy_flags.cc \
    $(BOCHS_DIR)/cpu/logical16.cc \
    $(BOCHS_DIR)/cpu/logical32.cc \
    $(BOCHS_DIR)/cpu/logical8.cc \
    $(BOCHS_DIR)/cpu/misc_i386.cc \
    $(BOCHS_DIR)/cpu/move16.cc \
    $(BOCHS_DIR)/cpu/move32.cc \
    $(BOCHS_DIR)/cpu/move8.cc \
    $(BOCHS_DIR)/cpu/mult16.cc \
    $(BOCHS_DIR)/cpu/mult32.cc \
    $(BOCHS_DIR)/cpu/mult8.cc \
    $(BOCHS_DIR)/cpu/proc_ctrl.cc \
    $(BOCHS_DIR)/cpu/push_pop.cc \
    $(BOCHS_DIR)/cpu/rep_cmps.cc \
    $(BOCHS_DIR)/cpu/rep_lods.cc \
    $(BOCHS_DIR)/cpu/rep_movs.cc \
    $(BOCHS_DIR)/cpu/rep_scas.cc \
    $(BOCHS_DIR)/cpu/rep_stos.cc \
    $(BOCHS_DIR)/cpu/rotate.cc \
    $(BOCHS_DIR)/cpu/segment_ctrl.cc \
    $(BOCHS_DIR)/cpu/shift.cc \
    $(BOCHS_DIR)/cpu/stack.cc \
    $(BOCHS_DIR)/cpu/string.cc \
    $(BOCHS_DIR)/cpu/tasking.cc \
    $(BOCHS_DIR)/cpu/decoder/ia_opcodes.cc \
    $(BOCHS_DIR)/cpu/decoder/decoder.cc

BOCHS_CPU_OBJS := $(patsubst $(BOCHS_DIR)/cpu/%.cc,$(BOCHS_BUILD)/%.o,$(BOCHS_CPU_SRCS))


# =============================================================================
# BUSYBOX
# =============================================================================

$(BUSYBOX_BIN):
	@echo "Downloading BusyBox 32-bit binary..."
	wget -O $(BUSYBOX_BIN) $(BUSYBOX_URL) || curl -L -o $(BUSYBOX_BIN) $(BUSYBOX_URL)
	@echo "BusyBox downloaded successfully"

ramdisk.o: $(BUSYBOX_BIN)
	@echo "Embedding BusyBox into ramdisk..."
	chmod +x $(BUSYBOX_BIN)
	objcopy -I binary -O elf32-i386 -B i386 \
		--rename-section .data=.rodata,alloc,load,readonly,data,contents \
		--redefine-sym _binary_busybox_start=ramdisk_start \
		--redefine-sym _binary_busybox_end=ramdisk_end \
		--redefine-sym _binary_busybox_size=ramdisk_size \
		$(BUSYBOX_BIN) ramdisk.o
	@echo "Ramdisk created successfully"


# =============================================================================
# BOCHS GLUE - wires Bochs memory to ELF process buffers
# =============================================================================
bochs_glue.cpp: $(BOCHS_CPU_LIB)
	@echo "Generating bochs_glue.cpp..."
	@printf '%s\n' \
	  '#include "$(BOCHS_DIR)/bochs.h"' \
	  '#include "$(BOCHS_DIR)/cpu/cpu.h"' \
	  '' \
	  'static unsigned char* g_mem_base = nullptr;' \
	  'static unsigned int   g_mem_size = 0;' \
	  'static unsigned char* g_stack    = nullptr;' \
	  '#define STACK_BASE 0x80000000u' \
	  '' \
	  'BX_CPU_C bx_cpu;' \
	  'BX_MEM_C bx_mem;' \
	  '' \
	  'void BX_MEM_C::read_physical(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data) {' \
	  '  unsigned char* out = (unsigned char*)data;' \
	  '  for (unsigned i = 0; i < len; i++) {' \
	  '    unsigned int a = addr + i;' \
	  '    if (a >= STACK_BASE && g_stack) {' \
	  '      unsigned off = a - STACK_BASE;' \
	  '      out[i] = (off < 65536) ? g_stack[off] : 0;' \
	  '    } else if (g_mem_base && a < g_mem_size) {' \
	  '      out[i] = g_mem_base[a];' \
	  '    } else { out[i] = 0; }' \
	  '  }' \
	  '}' \
	  '' \
	  'void BX_MEM_C::write_physical(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data) {' \
	  '  unsigned char* in = (unsigned char*)data;' \
	  '  for (unsigned i = 0; i < len; i++) {' \
	  '    unsigned int a = addr + i;' \
	  '    if (a >= STACK_BASE && g_stack) {' \
	  '      unsigned off = a - STACK_BASE;' \
	  '      if (off < 65536) g_stack[off] = in[i];' \
	  '    } else if (g_mem_base && a < g_mem_size) {' \
	  '      g_mem_base[a] = in[i];' \
	  '    }' \
	  '  }' \
	  '}' \
	  '' \
	  'extern "C" void bochs_set_process_memory(' \
	  '    unsigned char* base, unsigned int size, unsigned char* stack) {' \
	  '  g_mem_base = base; g_mem_size = size; g_stack = stack;' \
	  '}' \
	  '' \
	  'extern "C" void bochs_cpu_init() {' \
	  '  bx_cpu.initialize();' \
	  '  bx_cpu.reset(BX_RESET_HARDWARE);' \
	  '}' \
	  '' \
	  'extern "C" void bochs_cpu_set_eip(unsigned int eip) {' \
	  '  bx_cpu.prev_rip = bx_cpu.get_instruction_pointer();' \
	  '  bx_cpu.gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;' \
	  '}' \
	  '' \
	  'extern "C" void bochs_cpu_set_esp(unsigned int esp) {' \
	  '  bx_cpu.gen_reg[BX_32BIT_REG_ESP].dword.erx = esp;' \
	  '}' \
	  '' \
	  'extern "C" int bochs_cpu_tick(int steps) {' \
	  '  for (int i = 0; i < steps; i++) bx_cpu.cpu_loop();' \
	  '  return 0;' \
	  '}' \
	  '' \
	  'extern "C" unsigned int bochs_cpu_get_eax() {' \
	  '  return bx_cpu.gen_reg[BX_32BIT_REG_EAX].dword.erx;' \
	  '}' \
	  '' \
	  'extern "C" unsigned int bochs_cpu_get_eip() {' \
	  '  return bx_cpu.get_instruction_pointer();' \
	  '}' \
	  > bochs_glue.cpp

bochs_glue.o: bochs_glue.cpp $(BOCHS_CPU_LIB)
	gcc -c bochs_glue.cpp -m32 -O2 \
	    -I$(BOCHS_DIR) \
	    -I$(BOCHS_DIR)/cpu \
	    -Wno-unused-parameter \
	    -o bochs_glue.o

# =============================================================================
# BOCHS CPU OBJECTS
# =============================================================================

bochs-build: bochs-patch $(BOCHS_CPU_OBJS)

$(BOCHS_BUILD)/%.o: $(BOCHS_DIR)/cpu/%.cc $(BOCHS_DIR)/.patched
	
	
	@echo "Patching Bochs for standalone CPU use..."
	# Fix instrument.h include
	sed -i '364s/#include "instrument.h"/#ifdef BX_SUPPORT_INSTRUMENTATION\n#include "instrument.h"\n#endif/' $(BOCHS_DIR)/bochs.h
	# Alternative stub include if stubs dir missing
	echo '#ifndef BX_SUPPORT_INSTRUMENTATION' > $(BOCHS_DIR)/instrument.h
	echo '#define BX_INSTR_ENABLED(x)  ((void)0)' >> $(BOCHS_DIR)/instrument.h
	echo '#define BX_INSTR_FPU_ENABLED  ((void)0)' >> $(BOCHS_DIR)/instrument.h
	echo '#endif' >> $(BOCHS_DIR)/instrument.h
	ln -sf $(BOCHS_DIR)/instrument.h $(BOCHS_DIR)/instrument/stubs/instrument.h 2>/dev/null || true
	# Comment out other GUI/optional includes if needed
	sed -i 's/#include "param_names.h"/\/\/#include "param_names.h"/' $(BOCHS_DIR)/bochs.h
	@mkdir -p $(dir $@)
	@echo "[BOCHS] $<"
	gcc -c $< $(BOCHS_CXXFLAGS) -o $@

$(BOCHS_BUILD)/decoder/%.o: $(BOCHS_DIR)/cpu/decoder/%.cc $(BOCHS_DIR)/.patched
	@mkdir -p $(BOCHS_BUILD)/decoder
	@echo "[BOCHS DEC] $<"
	gcc -c $< $(BOCHS_CXXFLAGS) -o $@

# =============================================================================
# KERNEL
# =============================================================================

boot.o: boot.S
	@echo "Assembling boot code..."
	as -32 boot.S -o boot.o

kernel.o: kernel.cpp
	@echo "Compiling kernel..."
	gcc -c kernel.cpp $(CXXFLAGS) \
	    -I$(BOCHS_DIR) \
	    -I$(BOCHS_DIR)/cpu \
	    -o kernel.o

$(MULTIBOOT): boot.o kernel.o ramdisk.o bochs_glue.o $(BOCHS_CPU_LIB)
	mkdir -p $(ISODIR)/boot
	ld -m elf_i386 -T linker.ld \
	    boot.o kernel.o ramdisk.o \
	    bochs_glue.o \
	    --whole-archive $(BOCHS_CPU_LIB) --no-whole-archive \
	    -o $(MULTIBOOT)



$(MAIN): $(MULTIBOOT)
	@echo "Creating bootable ISO..."
	mkdir -p $(ISODIR)/boot/grub
	echo 'set timeout=3'               > $(ISODIR)/boot/grub/grub.cfg
	echo 'menuentry "MyOS" {'         >> $(ISODIR)/boot/grub/grub.cfg
	echo '  multiboot /boot/main.elf' >> $(ISODIR)/boot/grub/grub.cfg
	echo '  boot'                     >> $(ISODIR)/boot/grub/grub.cfg
	echo '}'                          >> $(ISODIR)/boot/grub/grub.cfg
	grub-mkrescue -o $(MAIN) $(ISODIR)
	@echo "ISO created: $(MAIN)"

# =============================================================================
# UTILITY
# =============================================================================

run: $(MAIN)
	@echo "Launching QEMU..."
	qemu-system-i386 -cdrom $(MAIN) -m 512M -vga std

clean:
	@echo "Cleaning build artifacts..."
	rm -rf *.o $(BUSYBOX_BIN) $(ISODIR) $(MAIN) \
	       $(BOCHS_BUILD) bochs_glue.cpp
	@echo "Clean complete"

# Update clean-all to remove new archive name
clean-all: clean
	rm -rf $(BOCHS_DIR) $(BOCHS_GH_ARCHIVE) bochs_glue.cpp

.PHONY: clean run all bochs-fetch bochs-patch bochs-build
