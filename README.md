a simple GUI interface OS with terminal windows, TCC compiler & bochs emulator.


CTRL-Q saves and exits text editor...


SATA port selection with 'disk_select'

guest programs require many '.h' files within the base directory for compiled programs to interface with the OS.

Ethernet: RTL8139, Intel e1000 and e1000e drivers with ARP/IPv4/ICMP/UDP/DHCP/DNS (shell: `ifconfig`, `dhcp`, `ping`, `nslookup`, `arp`).

TODO: TCP, WiFi, web browser & busybox implementation

TODO: add driver kit

# Build Instructions

## Prerequisites (one-time apt installs)

```bash
sudo apt update
sudo apt install make gcc g++ gcc-multilib g++-multilib gcc-13-multilib \
    binutils binutils-multiarch grub-common grub-pc-bin \
    xorriso mtools qemu-system-x86 build-essential nasm \
    libncurses-dev bison flex git bc libssl-dev \
    xorg-dev libx11-dev
```

> **Note:** `binutils-multiarch` is required for `ld -m elf_i386` used by
> the TCC guest linker step.  TCC itself is built from source automatically
> (see below) — no `apt install tcc` needed.

---

## TCC: download and build (one-time, automatic)

TCC (Tiny C Compiler) is fetched from GitHub and built locally into
`tcc-local/`.  This gives you `i386-tcc` (cross-compiler targeting 32-bit
i386) and `libtcc.a` (for `tcc_tool`).

```bash
make setup-tcc        # downloads source, builds, installs into tcc-local/
```

To remove the local TCC build and start fresh:

```bash
make tcc-clean        # removes tcc-local/, tcc-src/, tcc-mob.tar.gz
```

---

## Full kernel build

```bash
make clean
rm -rf bochs-2.0 bochs-2.0-src.tar.gz tcc-src tcc-local i386-libtcc-kern.a i386-libtcc.a
make
```

Run in QEMU:

```bash
qemu-system-i386 -M q35 -m 2048M -vga std \
    -drive id=cd0,file=main.iso,format=raw,if=none,media=cdrom \
    -drive id=disk0,file=disk.img,format=raw,if=none \
    -device ahci,id=ahci \
    -device ide-cd,drive=cd0,bus=ahci.0 \
    -device ide-hd,drive=disk0,bus=ahci.1 \
    -nic user,model=e1000 \
    -boot d
```

`-nic user,model=...` accepts `e1000`, `e1000e` or `rtl8139`. In QEMU user-mode
networking the guest gets 10.0.2.15 by DHCP; `ping 10.0.2.2` tests the link.
