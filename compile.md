sudo apt update

sudo apt install make gcc gcc-multilib binutils grub-common xorriso qemu-system-x86 build-essential nasm gcc binutils qemu-system-x86 xorriso grub-pc-bin mtools g++-multilib libncurses-dev bison flex git bc libssl-dev

# 1 Kernel Build

sudo make clean

sudo make

use VMware (other-64bit) with SATA drive, port 0


Optional:

# 2 Make a place for compiler sources
mkdir -p ~/opt/cross

cd ~/opt/cross

# 3 Download Binutils and GCC
wget https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.xz

wget https://ftp.gnu.org/gnu/gcc/gcc-14.1.0/gcc-14.1.0.tar.xz

tar -xf binutils-2.43.tar.xz

tar -xf gcc-14.2.0.tar.xz

# 4 Build binutils

mkdir build-binutils

cd build-binutils

../binutils-2.43/configure --target=i686-elf --prefix=/usr/local/cross --with-sysroot --disable-nls --disable-werror

make -j$(nproc)

sudo make install

cd ..

# 5 Build GCC

mkdir build-gcc

cd build-gcc

../gcc-14.2.0/configure --target=i686-elf --prefix=/usr/local/cross --disable-nls --enable-languages=c,c++ --without-headers

make all-gcc -j$(nproc)

make all-target-libgcc -j$(nproc)

sudo make install-gcc

sudo make install-target-libgcc


export PATH="/usr/local/cross/bin:$PATH"

export LIBRARY_PATH=/usr/lib/$(gcc -print-multiarch)

export C_INCLUDE_PATH=/usr/include/$(gcc -print-multiarch)

export CPLUS_INCLUDE_PATH=/usr/include/$(gcc -print-multiarch)


i686-elf-gcc --version

