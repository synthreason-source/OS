#include <stdint.h>
#include <stddef.h>
static inline void outb(uint16_t port, uint8_t val) { asm volatile ("outb %0, %1" : : "a"(val), "d"(port)); }
static inline void outl(uint16_t port, uint32_t val) { asm volatile ("outl %0, %1" : : "a"(val), "d"(port)); }
static inline uint8_t inb(uint16_t port) { uint8_t ret; asm volatile ("inb %1, %0" : "=a"(ret) : "d"(port)); return ret; }
static inline uint32_t inl(uint16_t port) { uint32_t ret; asm volatile ("inl %1, %0" : "=a"(ret) : "d"(port)); return ret; }
static inline uint32_t pci_read_config_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)device << 11) | ((uint32_t)function << 8) | (offset & 0xFC);
    outl(0xCF8, address); return inl(0xCFC);
}
static inline void pci_write_config_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)device << 11) | ((uint32_t)function << 8) | (offset & 0xFC);
    outl(0xCF8, address); outl(0xCFC, value);
}
static uint8_t g_heap[4*1024*1024]; static size_t g_hp;
extern "C" void* kernel_alloc_nofail(size_t n) { n = (n + 15) & ~15u; if (g_hp + n > sizeof(g_heap)) return 0; void* p = g_heap + g_hp; g_hp += n; return p; }
static void serial_putc(char c) { while (!(inb(0x3FD) & 0x20)); outb(0x3F8, c); }
void console_print(const char* s) { while (*s) serial_putc(*s++); }

#include "../kernel_parts/07b_network.h"

static uint32_t calibrate() {   // PIT ch2 one-shot ~10ms
    outb(0x61, (inb(0x61) & ~2) | 1);
    outb(0x43, 0xB0); outb(0x42, 11932 & 0xFF); outb(0x42, 11932 >> 8);   // 10 ms
    uint8_t g = inb(0x61) & ~1; outb(0x61, g); outb(0x61, g | 1);
    uint64_t t0 = net_rdtsc();
    while (!(inb(0x61) & 0x20));
    uint64_t t1 = net_rdtsc();
    return (uint32_t)(t1 - t0) / 10;
}
static void run(const char* cmd, const char* args) { char a[64]; int i = 0; while (args[i]) { a[i] = args[i]; i++; } a[i] = 0; console_print("> "); console_print(cmd); console_print(" "); console_print(args); console_print("\n"); net_run_command(cmd, a); }

#ifdef RXTEST
extern "C" void kmain() {
    outb(0x3F9, 0); outb(0x3FB, 0x03);
    uint32_t tpm = calibrate();
    net_init(tpm);
    run("ifconfig", "");
    console_print("LISTENING\n");
    uint64_t dl = net_deadline(12000);
    while (!net_expired(dl)) net_poll();
    console_print("DONE\n");
    outb(0x501, 0);
    for (;;) asm volatile("hlt");
}
#else
extern "C" void kmain() {
    outb(0x3F9, 0); outb(0x3FB, 0x03);
    uint32_t tpm = calibrate();
    char b[32]; net_u32(b, tpm); console_print("tsc/ms="); console_print(b); console_print("\n");
    bool ok = net_init(tpm);
    console_print(ok ? "net_init OK\n" : "net_init FAILED\n");
    run("ifconfig", "");
    run("arp", "");
    run("ping", "10.0.2.2 3");
    run("nslookup", "10.0.2.3");
    g_dns = 0x0A000202u; run("nslookup", "test.example.com"); run("ping", "test.example.com 2");
    run("arp", "");
    console_print("DONE\n");
    outb(0x501, 0);   // isa-debug-exit
    for (;;) asm volatile("hlt");
}
#endif
