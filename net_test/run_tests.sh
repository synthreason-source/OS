#!/bin/sh
# Standalone driver tests under QEMU (needs qemu-system-x86, gcc-multilib). Run from this directory.
# qemu exits non-zero via isa-debug-exit, so no "set -e"
CXX="g++ -m32 -O2 -ffreestanding -fno-pie -fno-pic -fno-exceptions -fno-rtti -fno-stack-protector -std=c++17 -Wall -Wno-unused-function"
gcc -m32 -c boot.S -o boot.o
$CXX -c test_net.cpp -o test_net.o && ld -m elf_i386 -T link.ld -o net.elf boot.o test_net.o
$CXX -DRXTEST -c test_net.cpp -o test_rx.o && ld -m elf_i386 -T link.ld -o rx.elf boot.o test_rx.o
for m in rtl8139 e1000 e1000e; do
  echo "== $m: DHCP / ping / arp"
  qemu-system-i386 -M q35 -m 256 -kernel net.elf -display none -serial stdio -monitor none -no-reboot \
    -device isa-debug-exit,iobase=0x501,iosize=1 -nic user,model=$m
  echo "== $m: receive path (ARP + ping to the guest)"
  python3 rx_test.py & sleep 1
  qemu-system-i386 -M q35 -m 256 -kernel rx.elf -display none -serial null -monitor none -no-reboot \
    -device isa-debug-exit,iobase=0x501,iosize=1 -netdev socket,id=n0,connect=127.0.0.1:12345 -device $m,netdev=n0
  wait
done
