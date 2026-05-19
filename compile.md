sudo apt update

sudo apt install make gcc-multilib gcc-13-multilib gcc gcc-13 binutils grub-common xorriso qemu-system-x86 build-essential nasm gcc binutils qemu-system-x86 xorriso grub-pc-bin mtools g++-multilib libncurses-dev bison flex git bc libssl-dev xorg-dev libx11-dev




# 1 Bochs test
sudo make test_main

qemu-system-i386 -cdrom test_main.iso -m 256 -debugcon stdio -no-reboot -no-shutdown


# 1 Kernel Build
sudo make clean

make clean && make BOCHS=1

qemu-system-i386 -M q35 -m 2048M -vga std     -drive id=cd0,file=main.iso,format=raw,if=none,media=cdrom     -drive id=disk0,file=disk.img,format=raw,if=none     -device ahci,id=ahci     -device ide-cd,drive=cd0,bus=ahci.0     -device ide-hd,drive=disk0,bus=ahci.1     -boot d
      
compatible with SATA drives, currently using port 0


