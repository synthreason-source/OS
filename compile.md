sudo apt update

sudo apt install make gcc-multilib gcc-13-multilib gcc gcc-13 binutils grub-common xorriso qemu-system-x86 build-essential nasm gcc binutils qemu-system-x86 xorriso grub-pc-bin mtools g++-multilib libncurses-dev bison flex git bc libssl-dev xorg-dev libx11-dev


# 1 Kernel Build

sudo make clean

make clean && make BOCHS=0 // must be 0 for bochs to work...

	qemu-system-i386 \
	    -M q35 \
	    -cdrom main.iso -boot d \
	    -m 8000M \
	    -vga std \
	    -drive id=disk0,file=disk.img,format=raw,if=none \
	    -device ahci,id=ahci \
	    -device ide-hd,drive=disk0,bus=ahci.0
      
use VMware (other-64bit) with SATA drive, port 0


