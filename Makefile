ISODIR := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN := main.iso
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra -std=c++17 -fno-exceptions -fno-rtti -m32 -include fixes.h 
CPPFLAGS += -include instrument_stub.h

# Bochs
BOCHS_VERSION := 2.7
BOCHS_DIR := bochs-$(BOCHS_VERSION)
BOCHS_GH_ARCHIVE := $(BOCHS_DIR).tar.gz
BOCHS_GH_URL := https://downloads.sourceforge.net/project/bochs/bochs/$(BOCHS_VERSION)/$(BOCHS_GH_ARCHIVE)
BOCHS_CPU_LIB := $(BOCHS_DIR)/cpu/.libs/libcpu.a

$(BOCHS_GH_ARCHIVE):
	wget -O $@ $(BOCHS_GH_URL) || curl -L -o $@ $(BOCHS_GH_URL)

$(BOCHS_DIR)/.extracted: $(BOCHS_GH_ARCHIVE)
	tar -xzf $(BOCHS_GH_ARCHIVE)
	touch $(BOCHS_DIR)/.extracted
	

ISODIR := iso
MAIN := main.iso
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra -std=c++17 -fno-exceptions -fno-rtti -m32
BOCHS_DIR := bochs-2.7
BOCHS_CPU_LIB := $(BOCHS_DIR)/cpu/.libs/libcpu.a

all: $(MAIN)

$(BOCHS_CPU_LIB):
	rm -rf $(BOCHS_DIR)
	wget -O temp.tar.gz https://downloads.sourceforge.net/project/bochs/bochs/2.7/$(BOCHS_DIR).tar.gz
	tar -xzf temp.tar.gz
	mv $(BOCHS_DIR) temp-bochs && mv temp-bochs $(BOCHS_DIR)
	rm temp.tar.gz
	cd $(BOCHS_DIR) && ./configure \
		--enable-cpu-level=6 --enable-fpu \
		--disable-mmx --disable-sse --disable-avx \
		--disable-x86-64 --disable-debugger \
		CXXFLAGS="-O2 -m32" CFLAGS="-O2 -m32"
	# Inject the define BEFORE bochs.h is processed, at the very top
	sed -i '1s/^/#define BX_SUPPORT_INSTRUMENTATION 1\n/' $(BOCHS_DIR)/bochs.h
	# Point Bochs at the stub instrument header
	sed -i 's|instrument/stubs/instrument.h|../instrument/stubs/instrument.h|g' $(BOCHS_DIR)/cpu/*.cc $(BOCHS_DIR)/cpu/*.h || true
	cd $(BOCHS_DIR)/cpu && make

bochs_glue.cpp: $(BOCHS_CPU_LIB)
	echo '#include "$(BOCHS_DIR)/bochs.h"' >> bochs_glue.cpp
	echo '#include "$(BOCHS_DIR)/cpu/cpu.h"' >> bochs_glue.cpp
	echo 'static BX_CPU_C bx_cpu;' >> bochs_glue.cpp
	echo 'extern "C" void bochs_cpu_init(){bx_cpu.initialize(); bx_cpu.reset(BX_RESET_HARDWARE);}' >> bochs_glue.cpp
	echo 'extern "C" int bochs_cpu_tick(int n){for(int i=0;i<n;i++)bx_cpu.cpu_loop();return 0;}' >> bochs_glue.cpp
	echo 'extern "C" unsigned int bochs_cpu_get_eip(){return bx_cpu.get_instruction_pointer();}' >> bochs_glue.cpp

bochs_glue.o: bochs_glue.cpp $(BOCHS_CPU_LIB)
	g++ -m32 -O2 -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu $(CXXFLAGS) -c bochs_glue.cpp -o $@

boot.o: boot.S
	as --32 boot.S -o boot.o

kernel.o: kernel.cpp $(BOCHS_CPU_LIB)
	g++ -m32 -O2 -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu $(CXXFLAGS) -c kernel.cpp -o kernel.o

$(MULTIBOOT): boot.o kernel.o ramdisk.o bochs_glue.o $(BOCHS_CPU_LIB)
	mkdir -p iso/boot
	ld -m elf_i386 -T linker.ld -o iso/boot/main.elf boot.o kernel.o ramdisk.o bochs_glue.o $(BOCHS_CPU_LIB)

$(MAIN): $(MULTIBOOT)
	mkdir -p iso/boot/grub
	echo 'set timeout=0
	menuentry "OS" { multiboot /boot/main.elf }' > iso/boot/grub/grub.cfg
	grub-mkrescue -o main.iso iso

run: $(MAIN)
	qemu-system-i386 -cdrom main.iso -m 128M

clean:
	rm -rf *.o iso main.iso bochs-2.7 $(BOCHS_CPU_LIB)

.PHONY: all run clean
