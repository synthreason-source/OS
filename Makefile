.POSIX:
ISODIR := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN := main.iso
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra -std=c++17 -fno-exceptions -fno-rtti -m32
# BusyBox 32-bit binary URL and local filename
BUSYBOX_URL := https://busybox.net/downloads/binaries/1.35.0-i686-linux-musl/busybox
BUSYBOX_BIN := busybox

.PHONY: clean run all

all: $(MAIN)

# Download BusyBox 32-bit binary if not present
$(BUSYBOX_BIN):
	@echo "Downloading BusyBox 32-bit binary..."
	wget -O $(BUSYBOX_BIN) $(BUSYBOX_URL) || curl -L -o $(BUSYBOX_BIN) $(BUSYBOX_URL)
	@echo "BusyBox downloaded successfully"
	
# Embed BusyBox binary into the kernel as a ramdisk
ramdisk.o: $(BUSYBOX_BIN)
	@echo "Embedding BusyBox into ramdisk..."
	chmod +x $(BUSYBOX_BIN)
	objcopy -I binary -O elf32-i386 -B i386:x86-64 \
		--rename-section .data=.rodata,alloc,load,readonly,data,contents \
		--redefine-sym _binary_busybox_start=ramdisk_start \
		--redefine-sym _binary_busybox_end=ramdisk_end \
		--redefine-sym _binary_busybox_size=ramdisk_size \
		$(BUSYBOX_BIN) ramdisk.o
	@echo "Ramdisk created successfully"



boot.o: boot.S
	@echo "Assembling boot code..."
	as -32 boot.S -o boot.o

kernel.o: kernel.cpp
	@echo "Compiling kernel..."
	gcc -c kernel.cpp $(CXXFLAGS) -o kernel.o

# Link kernel with boot code and embedded ramdisk
$(MULTIBOOT): boot.o kernel.o ramdisk.o
	@echo "Linking kernel with embedded BusyBox ramdisk..."
	mkdir -p $(ISODIR)/boot
	ld -m elf_i386 -T linker.ld boot.o kernel.o ramdisk.o -o $(MULTIBOOT)
	@echo "Kernel ELF created: $(MULTIBOOT)"

# Create bootable ISO with GRUB
$(MAIN): $(MULTIBOOT)
	@echo "Creating bootable ISO..."
	mkdir -p $(ISODIR)/boot/grub
	echo 'set timeout=3' > $(ISODIR)/boot/grub/grub.cfg
	echo 'menuentry "MyOS" {' >> $(ISODIR)/boot/grub/grub.cfg
	echo '  multiboot /boot/main.elf' >> $(ISODIR)/boot/grub/grub.cfg
	echo '  boot' >> $(ISODIR)/boot/grub/grub.cfg
	echo '}' >> $(ISODIR)/boot/grub/grub.cfg
	grub-mkrescue -o $(MAIN) $(ISODIR)
	@echo "ISO created: $(MAIN)"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf *.o $(BUSYBOX_BIN) $(ISODIR) $(MULTIBOOT) $(MAIN)
	@echo "Clean complete"

run: $(MAIN)
	@echo "Launching QEMU..."
	qemu-system-i386 -cdrom $(MAIN) -m 512M