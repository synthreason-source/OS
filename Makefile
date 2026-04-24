ISODIR := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN := main.iso
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra -fno-use-cxa-atexit -std=c++17 -fno-exceptions -fno-rtti -m32 -include fixes.h -Wl,--unresolved-symbols=ignore-all
CPPFLAGS += -include instrument_stub.h

# Bochs
BOCHS_VERSION := 2.7
BOCHS_DIR := bochs-$(BOCHS_VERSION)
BOCHS_GH_ARCHIVE := $(BOCHS_DIR).tar.gz
BOCHS_GH_URL := https://downloads.sourceforge.net/project/bochs/bochs/$(BOCHS_VERSION)/$(BOCHS_GH_ARCHIVE)
BOCHS_CPU_LIB := $(BOCHS_DIR)/cpu/libcpu.a

$(BOCHS_GH_ARCHIVE):
	wget -O $@ $(BOCHS_GH_URL) || curl -L -o $@ $(BOCHS_GH_URL)

$(BOCHS_DIR)/.extracted: $(BOCHS_GH_ARCHIVE)
	tar -xzf $(BOCHS_GH_ARCHIVE)
	touch $(BOCHS_DIR)/.extracted
	

ISODIR := iso
MAIN := main.iso
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra -std=c++17 -fno-exceptions -fno-rtti -m32
BOCHS_DIR := bochs-2.7
BOCHS_CPU_LIB := $(BOCHS_DIR)/cpu/libcpu.a

all: $(MAIN)
$(BOCHS_CPU_LIB):
	wget -O temp.tar.gz https://downloads.sourceforge.net/project/bochs/bochs/2.7/$(BOCHS_DIR).tar.gz
	tar -xzf temp.tar.gz
	rm temp.tar.gz
		cd $(BOCHS_DIR) && ./configure \
		--enable-cpu-level=6 --enable-fpu \
		--disable-mmx --disable-sse --disable-avx \
		--disable-x86-64 --disable-debugger \
		--with-nogui --disable-gui \
		CXXFLAGS="-O2 -m32 -fno-stack-protector" \
		CFLAGS="-O2 -m32 -fno-stack-protector"
	cd $(BOCHS_DIR) && make

bochs_glue.cpp: $(BOCHS_CPU_LIB)
	printf '%s\n' \
		'#ifndef BX_INSTRUMENT_H' \
		'#define BX_INSTRUMENT_H' \
		'#define BX_INSTR_PHY_ACCESS(cpu_id, paddr, size, memtype, rw)' \
		'#define BX_INSTR_CACHE_CNTRL(cpu_id, what)' \
		'#define BX_INSTR_CLFLUSH(cpu_id, laddr, paddr)' \
		'#define BX_INSTR_TLB_CNTRL(cpu_id, what, new_cr3)' \
		'#define BX_INSTR_WRMSR(cpu_id, addr, val64)' \
		'#define BX_INSTR_OPCODE(cpu_id, i, opcode, len, is32, is64)' \
		'#define BX_INSTR_UCNEAR_BRANCH(cpu_id, what, orig_rip, new_rip)' \
		'#define BX_INSTR_CNEAR_BRANCH_TAKEN(cpu_id, orig_rip, new_rip)' \
		'#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(cpu_id, orig_rip)' \
		'#define BX_INSTR_FAR_BRANCH(cpu_id, what, prev_cs, prev_rip, new_cs, new_rip)' \
		'#define BX_INSTR_FAR_BRANCH_ORIGIN()' \
		'#define BX_INSTR_IS_INT(cpu_id)       (0)' \
		'#define BX_INSTR_INIT_ENV()' \
		'#define BX_INSTR_EXIT_ENV()' \
		'#define BX_INSTR_INITIALIZE(cpu_id)' \
		'#define BX_INSTR_EXIT(cpu_id)' \
		'#define BX_INSTR_RESET(cpu_id, source)' \
		'#define BX_INSTR_HLT(cpu_id)' \
		'#define BX_INSTR_MWAIT(cpu_id, addr, len, flags)' \
		'#define BX_INSTR_CNT(cpu_id)' \
		'#define BX_INSTR_BEFORE_EXECUTION(cpu_id, i)' \
		'#define BX_INSTR_AFTER_EXECUTION(cpu_id, i)' \
		'#define BX_INSTR_REPEAT_ITERATION(cpu_id, i)' \
		'#define BX_INSTR_INP(addr, len)' \
		'#define BX_INSTR_INP2(addr, len, val)' \
		'#define BX_INSTR_OUTP(addr, len, val)' \
		'#define BX_INSTR_MEM_PHY_READ(cpu_id, addr, len)' \
		'#define BX_INSTR_MEM_PHY_WRITE(cpu_id, addr, len)' \
		'#define BX_INSTR_MEM_PHY_ACCESS(cpu_id, addr, rw, len)' \
		'#define BX_INSTR_LIN_ACCESS(cpu_id, lin, phy, len, memtype, rw)' \
		'#define BX_INSTR_MEM_DATA(cpu_id, seg, off, len, rw)' \
		'#define BX_INSTR_INTERRUPT(cpu_id, vector)' \
		'#define BX_INSTR_EXCEPTION(cpu_id, vector, error_code)' \
		'#define BX_INSTR_HWINTERRUPT(cpu_id, vector, cs, eip)' \
		'#define BX_INSTR_WRMSR(cpu_id, addr, val64)' \
		'#define BX_INSTR_IS_INT(cpu_id)       (0)' \
		'#define BX_INSTR_IS_RET(cpu_id)       (0)' \
		'#define BX_INSTR_IS_CALL(cpu_id)      (0)' \
		'#define BX_INSTR_IS_IRET(cpu_id)      (0)' \
		'#define BX_INSTR_IS_CALL_NEAR(cpu_id) (0)' \
		'#define BX_INSTR_IS_CALL_FAR(cpu_id)  (0)' \
		'#endif' \
	> $(BOCHS_DIR)/instrument.h

bochs_glue.o: bochs_glue.cpp $(BOCHS_CPU_LIB)
	g++ -m32 -O2 -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu $(CXXFLAGS) -c bochs_glue.cpp -o $@

boot.o: boot.S
	as --32 boot.S -o boot.o

kernel.o: kernel.cpp $(BOCHS_CPU_LIB)
	g++ -m32 -O2 -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu $(CXXFLAGS) -c kernel.cpp -o kernel.o
	
$(MULTIBOOT): boot.o kernel.o bochs_glue.o $(BOCHS_CPU_LIB)
	mkdir -p iso/boot
	g++ -m32 -T linker.ld -nostdlib -o iso/boot/main.elf boot.o kernel.o bochs_glue.o \
		$(BOCHS_DIR)/cpu/libcpu.a \
		$(BOCHS_DIR)/cpu/fpu/libfpu.a \
		$(BOCHS_DIR)/cpu/cpudb/libcpudb.a \
		$(BOCHS_DIR)/memory/libmemory.a \
		-lgcc -Wl,--unresolved-symbols=ignore-all

$(MAIN): $(MULTIBOOT)
	mkdir -p iso/boot/grub
	echo 'menuentry "OS" { multiboot /boot/main.elf }' > iso/boot/grub/grub.cfg
	grub-mkrescue -o main.iso iso

run: $(MAIN)
	qemu-system-i386 -cdrom main.iso -m 128M

clean:
	rm -rf *.o iso main.iso bochs-2.7 $(BOCHS_CPU_LIB)

.PHONY: all run clean