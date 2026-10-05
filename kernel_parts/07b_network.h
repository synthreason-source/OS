#pragma once
// 07b_network.h
// Ethernet NIC drivers + a small IPv4 stack, polled (no IRQs needed).
//
//   NIC drivers : Realtek RTL8139 (10EC:8139)
//                 Intel e1000 / e1000e (8086:100E, 100F, 10D3)
//   Stack       : ARP, IPv4, ICMP echo, UDP, DHCP client, DNS (A records)
//   Shell cmds  : ifconfig, dhcp, ping, nslookup, arp   (net_run_command)
//
// Included from kernel.cpp right after 07_chkdsk_and_hardware.h, so it can use
// outb/outl/inb/inl, pci_read/write_config_dword, kernel_alloc_nofail() and
// console_print().  Everything is prefixed net_/rtl_/e1k_ to avoid clashes.
//
// DMA buffers come from the kernel heap; this kernel runs identity-mapped
// (the AHCI driver already hands virtual addresses to hardware), so a heap
// pointer IS the physical address.

// ───────────────────────────── low-level helpers ─────────────────────────────
static inline void     net_outw(uint16_t p, uint16_t v) { asm volatile("outw %0, %1" : : "a"(v), "d"(p)); }
static inline uint16_t net_inw (uint16_t p) { uint16_t r; asm volatile("inw %1, %0" : "=a"(r) : "d"(p)); return r; }
static inline uint64_t net_rdtsc() { uint32_t lo, hi; asm volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }
static inline void     net_pause() { asm volatile("pause"); }

static uint32_t g_net_tsc_per_ms = 2000000;   // overwritten by net_init()

static inline uint64_t net_deadline(uint32_t ms) { return net_rdtsc() + (uint64_t)ms * g_net_tsc_per_ms; }
static inline bool     net_expired(uint64_t dl)  { return net_rdtsc() >= dl; }

static void net_cpy(void* d, const void* s, uint32_t n) { uint8_t* a = (uint8_t*)d; const uint8_t* b = (const uint8_t*)s; while (n--) *a++ = *b++; }
static void net_zero(void* d, uint32_t n) { uint8_t* a = (uint8_t*)d; while (n--) *a++ = 0; }
static bool net_eq(const void* x, const void* y, uint32_t n) { const uint8_t* a = (const uint8_t*)x; const uint8_t* b = (const uint8_t*)y; while (n--) if (*a++ != *b++) return false; return true; }
static uint32_t net_slen(const char* s) { uint32_t n = 0; while (s && s[n]) n++; return n; }
static bool net_seq(const char* a, const char* b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

static inline uint16_t net_h16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }   // host<->net
static inline uint32_t net_h32(uint32_t v) { return (v >> 24) | ((v >> 8) & 0xFF00u) | ((v << 8) & 0xFF0000u) | (v << 24); }

static void* net_alloc_aligned(uint32_t size, uint32_t align) {
    uint8_t* p = (uint8_t*)kernel_alloc_nofail(size + align);
    if (!p) return nullptr;
    uintptr_t a = ((uintptr_t)p + (align - 1)) & ~(uintptr_t)(align - 1);
    net_zero((void*)a, size);
    return (void*)a;
}

// ───────────────────────────────── NIC state ─────────────────────────────────
enum { NIC_NONE = 0, NIC_RTL8139 = 1, NIC_E1000 = 2 };

static int       g_nic_type = NIC_NONE;
static char      g_nic_name[32] = "none";
static uint8_t   g_mac[6];
static uint16_t  g_nic_io;                    // RTL8139 I/O base
static volatile uint8_t* g_nic_mmio;          // e1000 MMIO base

// ───────────────────────────────── PCI scan ──────────────────────────────────
static void net_pci_enable(uint16_t bus, uint8_t dev, uint8_t fn) {
    uint32_t cmd = pci_read_config_dword(bus, dev, fn, 0x04) & 0xFFFFu;   // keep status bits (W1C) at 0
    pci_write_config_dword(bus, dev, fn, 0x04, cmd | 0x7u);               // I/O + memory + bus master
}

// ─────────────────────────────── RTL8139 driver ──────────────────────────────
#define RTL_IDR0   0x00
#define RTL_TSD0   0x10
#define RTL_TSAD0  0x20
#define RTL_RBSTART 0x30
#define RTL_CR     0x37
#define RTL_CAPR   0x38
#define RTL_IMR    0x3C
#define RTL_ISR    0x3E
#define RTL_TCR    0x40
#define RTL_RCR    0x44
#define RTL_CONFIG1 0x52
#define RTL_MSR    0x58

#define RTL_RX_SIZE 8192
static uint8_t* g_rtl_rx;
static uint32_t g_rtl_rx_off;
static uint8_t* g_rtl_tx[4];
static bool     g_rtl_tx_used[4];
static int      g_rtl_tx_cur;

static void rtl_rx_start() {
    g_rtl_rx_off = 0;
    outb(g_nic_io + RTL_CR, 0x04);                       // TE only (RX off)
    outl(g_nic_io + RTL_RBSTART, (uint32_t)(uintptr_t)g_rtl_rx);
    // accept broadcast + multicast + our MAC, WRAP, unlimited DMA burst
    outl(g_nic_io + RTL_RCR, 0x0Eu | (1u << 7) | (7u << 8));
    outb(g_nic_io + RTL_CR, 0x0C);                       // RE + TE
    net_outw(g_nic_io + RTL_CAPR, 0xFFF0);
    net_outw(g_nic_io + RTL_ISR, 0xFFFF);
}

static bool rtl_init(uint16_t bus, uint8_t dev, uint8_t fn) {
    uint32_t bar0 = pci_read_config_dword(bus, dev, fn, 0x10);
    if (!(bar0 & 1)) return false;                       // need the I/O BAR
    g_nic_io = (uint16_t)(bar0 & ~3u);
    net_pci_enable(bus, dev, fn);

    outb(g_nic_io + RTL_CONFIG1, 0x00);                  // power on
    outb(g_nic_io + RTL_CR, 0x10);                       // software reset
    uint64_t dl = net_deadline(200);
    while ((inb(g_nic_io + RTL_CR) & 0x10) && !net_expired(dl)) net_pause();
    if (inb(g_nic_io + RTL_CR) & 0x10) return false;

    for (int i = 0; i < 6; i++) g_mac[i] = inb(g_nic_io + RTL_IDR0 + i);

    g_rtl_rx = (uint8_t*)net_alloc_aligned(RTL_RX_SIZE + 16 + 1536 + 64, 256);
    for (int i = 0; i < 4; i++) g_rtl_tx[i] = (uint8_t*)net_alloc_aligned(1792, 4);
    if (!g_rtl_rx || !g_rtl_tx[0] || !g_rtl_tx[1] || !g_rtl_tx[2] || !g_rtl_tx[3]) return false;

    net_outw(g_nic_io + RTL_IMR, 0x0000);                // polled: no interrupts
    outl(g_nic_io + RTL_TCR, (3u << 24) | (6u << 8));    // IFG normal, DMA burst 1024
    rtl_rx_start();
    g_rtl_tx_cur = 0;
    for (int i = 0; i < 4; i++) g_rtl_tx_used[i] = false;
    return true;
}

static bool rtl_link_up() { return !(inb(g_nic_io + RTL_MSR) & 0x04); }

static bool rtl_send(const uint8_t* d, uint32_t len) {
    int i = g_rtl_tx_cur;
    if (g_rtl_tx_used[i]) {                              // wait for the previous DMA on this slot
        uint64_t dl = net_deadline(100);
        while (!(inl(g_nic_io + RTL_TSD0 + 4 * i) & 0x2000) && !net_expired(dl)) net_pause();
    }
    if (len > 1514) return false;
    net_cpy(g_rtl_tx[i], d, len);
    if (len < 60) { net_zero(g_rtl_tx[i] + len, 60 - len); len = 60; }
    outl(g_nic_io + RTL_TSAD0 + 4 * i, (uint32_t)(uintptr_t)g_rtl_tx[i]);
    outl(g_nic_io + RTL_TSD0 + 4 * i, len | (256u << 11 & 0x3F0000u));   // writing clears OWN -> start
    g_rtl_tx_used[i] = true;
    g_rtl_tx_cur = (i + 1) & 3;
    return true;
}

static void net_input(const uint8_t* f, uint32_t len);   // stack entry, defined below

static void rtl_poll() {
    for (int n = 0; n < 16; n++) {
        if (inb(g_nic_io + RTL_CR) & 0x01) break;        // BUFE: ring empty
        uint8_t* h = g_rtl_rx + g_rtl_rx_off;
        uint16_t st  = *(volatile uint16_t*)h;
        uint16_t len = *(volatile uint16_t*)(h + 2);
        if (!(st & 1) || len < 18 || len > 1518 + 4) { rtl_rx_start(); break; }   // corrupt ring: restart RX
        net_input(h + 4, (uint32_t)len - 4);             // len includes the 4-byte CRC
        g_rtl_rx_off = (g_rtl_rx_off + len + 4 + 3) & ~3u;
        if (g_rtl_rx_off >= RTL_RX_SIZE) g_rtl_rx_off -= RTL_RX_SIZE;
        net_outw(g_nic_io + RTL_CAPR, (uint16_t)(g_rtl_rx_off - 16));
        net_outw(g_nic_io + RTL_ISR, 0x0005);            // ack ROK/TOK
    }
}

// ───────────────────────────── Intel e1000 driver ────────────────────────────
#define E1K_CTRL  0x0000
#define E1K_STATUS 0x0008
#define E1K_ICR   0x00C0
#define E1K_IMC   0x00D8
#define E1K_RCTL  0x0100
#define E1K_TCTL  0x0400
#define E1K_TIPG  0x0410
#define E1K_RDBAL 0x2800
#define E1K_RDBAH 0x2804
#define E1K_RDLEN 0x2808
#define E1K_RDH   0x2810
#define E1K_RDT   0x2818
#define E1K_TDBAL 0x3800
#define E1K_TDBAH 0x3804
#define E1K_TDLEN 0x3808
#define E1K_TDH   0x3810
#define E1K_TDT   0x3818
#define E1K_MTA   0x5200
#define E1K_RAL0  0x5400
#define E1K_RAH0  0x5404

#define E1K_NRX 32
#define E1K_NTX 8
struct __attribute__((packed)) E1kRxDesc { uint32_t addr_lo, addr_hi; uint16_t length, csum; uint8_t status, errors; uint16_t special; };
struct __attribute__((packed)) E1kTxDesc { uint32_t addr_lo, addr_hi; uint16_t length; uint8_t cso, cmd, status, css; uint16_t special; };

static volatile E1kRxDesc* g_e1k_rx;
static volatile E1kTxDesc* g_e1k_tx;
static uint8_t* g_e1k_rxbuf;     // E1K_NRX * 2048
static uint8_t* g_e1k_txbuf;     // E1K_NTX * 2048
static uint32_t g_e1k_rx_next;
static uint32_t g_e1k_tx_next;
static bool     g_e1k_tx_used[E1K_NTX];

static inline uint32_t e1k_rd(uint32_t off) { return *(volatile uint32_t*)(g_nic_mmio + off); }
static inline void     e1k_wr(uint32_t off, uint32_t v) { *(volatile uint32_t*)(g_nic_mmio + off) = v; }

static bool e1k_init(uint16_t bus, uint8_t dev, uint8_t fn) {
    uint32_t bar0 = pci_read_config_dword(bus, dev, fn, 0x10);
    if (bar0 & 1) return false;                          // must be memory BAR
    g_nic_mmio = (volatile uint8_t*)(uintptr_t)(bar0 & ~0xFu);
    net_pci_enable(bus, dev, fn);

    e1k_wr(E1K_IMC, 0xFFFFFFFFu);                        // mask everything
    e1k_wr(E1K_CTRL, e1k_rd(E1K_CTRL) | (1u << 26));     // RST
    uint64_t dl = net_deadline(20);
    while (!net_expired(dl)) net_pause();                // datasheet: wait >= a few µs
    dl = net_deadline(200);
    while ((e1k_rd(E1K_CTRL) & (1u << 26)) && !net_expired(dl)) net_pause();
    e1k_wr(E1K_IMC, 0xFFFFFFFFu);
    (void)e1k_rd(E1K_ICR);

    uint32_t ctrl = e1k_rd(E1K_CTRL);
    ctrl |= (1u << 6) | (1u << 5);                       // SLU | ASDE
    ctrl &= ~((1u << 3) | (1u << 31) | (1u << 30));      // clear LRST, PHY_RST, VME
    e1k_wr(E1K_CTRL, ctrl);

    uint32_t ral = e1k_rd(E1K_RAL0), rah = e1k_rd(E1K_RAH0);
    g_mac[0] = ral & 0xFF; g_mac[1] = (ral >> 8) & 0xFF; g_mac[2] = (ral >> 16) & 0xFF; g_mac[3] = ral >> 24;
    g_mac[4] = rah & 0xFF; g_mac[5] = (rah >> 8) & 0xFF;
    if ((g_mac[0] | g_mac[1] | g_mac[2] | g_mac[3] | g_mac[4] | g_mac[5]) == 0) return false;   // no MAC -> unsupported variant
    e1k_wr(E1K_RAL0, ral);
    e1k_wr(E1K_RAH0, (rah & 0xFFFFu) | (1u << 31));      // address valid
    for (int i = 0; i < 128; i++) e1k_wr(E1K_MTA + i * 4, 0);

    g_e1k_rx    = (volatile E1kRxDesc*)net_alloc_aligned(E1K_NRX * 16, 128);
    g_e1k_tx    = (volatile E1kTxDesc*)net_alloc_aligned(E1K_NTX * 16, 128);
    g_e1k_rxbuf = (uint8_t*)net_alloc_aligned(E1K_NRX * 2048, 16);
    g_e1k_txbuf = (uint8_t*)net_alloc_aligned(E1K_NTX * 2048, 16);
    if (!g_e1k_rx || !g_e1k_tx || !g_e1k_rxbuf || !g_e1k_txbuf) return false;

    for (int i = 0; i < E1K_NRX; i++) {
        g_e1k_rx[i].addr_lo = (uint32_t)(uintptr_t)(g_e1k_rxbuf + i * 2048);
        g_e1k_rx[i].addr_hi = 0;
        g_e1k_rx[i].status = 0;
    }
    e1k_wr(E1K_RDBAL, (uint32_t)(uintptr_t)g_e1k_rx);
    e1k_wr(E1K_RDBAH, 0);
    e1k_wr(E1K_RDLEN, E1K_NRX * 16);
    e1k_wr(E1K_RDH, 0);
    e1k_wr(E1K_RDT, E1K_NRX - 1);
    g_e1k_rx_next = 0;
    // EN | MPE | BAM | 2048-byte buffers | strip CRC
    e1k_wr(E1K_RCTL, (1u << 1) | (1u << 4) | (1u << 15) | (1u << 26));

    e1k_wr(E1K_TDBAL, (uint32_t)(uintptr_t)g_e1k_tx);
    e1k_wr(E1K_TDBAH, 0);
    e1k_wr(E1K_TDLEN, E1K_NTX * 16);
    e1k_wr(E1K_TDH, 0);
    e1k_wr(E1K_TDT, 0);
    g_e1k_tx_next = 0;
    for (int i = 0; i < E1K_NTX; i++) g_e1k_tx_used[i] = false;
    e1k_wr(E1K_TIPG, 0x0060200Au);
    e1k_wr(E1K_TCTL, (1u << 1) | (1u << 3) | (0x10u << 4) | (0x40u << 12));   // EN | PSP | CT | COLD
    return true;
}

static bool e1k_link_up() { return (e1k_rd(E1K_STATUS) & 2) != 0; }

static bool e1k_send(const uint8_t* d, uint32_t len) {
    if (len > 1514) return false;
    uint32_t i = g_e1k_tx_next;
    if (g_e1k_tx_used[i]) {
        uint64_t dl = net_deadline(100);
        while (!(g_e1k_tx[i].status & 1) && !net_expired(dl)) net_pause();
        if (!(g_e1k_tx[i].status & 1)) return false;
    }
    uint8_t* b = g_e1k_txbuf + i * 2048;
    net_cpy(b, d, len);
    if (len < 60) { net_zero(b + len, 60 - len); len = 60; }
    g_e1k_tx[i].addr_lo = (uint32_t)(uintptr_t)b;
    g_e1k_tx[i].addr_hi = 0;
    g_e1k_tx[i].length  = (uint16_t)len;
    g_e1k_tx[i].cso = 0;
    g_e1k_tx[i].css = 0;
    g_e1k_tx[i].special = 0;
    g_e1k_tx[i].status = 0;
    g_e1k_tx[i].cmd = 0x0B;                              // EOP | IFCS | RS
    asm volatile("" ::: "memory");
    g_e1k_tx_used[i] = true;
    g_e1k_tx_next = (i + 1) % E1K_NTX;
    e1k_wr(E1K_TDT, g_e1k_tx_next);
    return true;
}

static void e1k_poll() {
    for (int n = 0; n < 16; n++) {
        uint32_t i = g_e1k_rx_next;
        if (!(g_e1k_rx[i].status & 1)) break;            // DD
        uint32_t len = g_e1k_rx[i].length;
        if ((g_e1k_rx[i].status & 2) && len >= 14 && len <= 2048 && g_e1k_rx[i].errors == 0)   // EOP, no errors
            net_input(g_e1k_rxbuf + i * 2048, len);
        g_e1k_rx[i].status = 0;
        e1k_wr(E1K_RDT, i);                              // hand the slot back
        g_e1k_rx_next = (i + 1) % E1K_NRX;
    }
}

// ─────────────────────────── NIC-independent entry points ────────────────────
static bool net_send_frame(const uint8_t* d, uint32_t len) {
    if (g_nic_type == NIC_RTL8139) return rtl_send(d, len);
    if (g_nic_type == NIC_E1000)   return e1k_send(d, len);
    return false;
}
static bool net_link_up() {
    if (g_nic_type == NIC_RTL8139) return rtl_link_up();
    if (g_nic_type == NIC_E1000)   return e1k_link_up();
    return false;
}

static bool g_net_in_poll = false;
static void net_poll() {                                 // call often; re-entrancy safe
    if (g_nic_type == NIC_NONE || g_net_in_poll) return;
    g_net_in_poll = true;
    if (g_nic_type == NIC_RTL8139) rtl_poll(); else e1k_poll();
    g_net_in_poll = false;
}

// ──────────────────────────────── protocol layer ─────────────────────────────
struct __attribute__((packed)) NetEth  { uint8_t dst[6], src[6]; uint16_t type; };
struct __attribute__((packed)) NetArp  { uint16_t htype, ptype; uint8_t hlen, plen; uint16_t op; uint8_t sha[6]; uint8_t spa[4]; uint8_t tha[6]; uint8_t tpa[4]; };
struct __attribute__((packed)) NetIp   { uint8_t vihl, tos; uint16_t len, id, frag; uint8_t ttl, proto; uint16_t csum; uint8_t src[4], dst[4]; };
struct __attribute__((packed)) NetIcmp { uint8_t type, code; uint16_t csum, id, seq; };
struct __attribute__((packed)) NetUdp  { uint16_t sport, dport, len, csum; };

static uint32_t g_ip = 0, g_mask = 0xFFFFFF00u, g_gw = 0, g_dns = 0;   // host byte order: a<<24|b<<16|c<<8|d
static bool     g_net_configured = false;

static inline void     net_put_ip(uint8_t* o, uint32_t ip) { o[0] = ip >> 24; o[1] = ip >> 16; o[2] = ip >> 8; o[3] = ip; }
static inline uint32_t net_get_ip(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static uint16_t net_csum(const void* data, uint32_t len, uint32_t sum = 0) {
    const uint8_t* p = (const uint8_t*)data;
    while (len > 1) { sum += ((uint32_t)p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len) sum += (uint32_t)p[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static const uint8_t NET_BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ARP cache ------------------------------------------------------------------
struct NetArpEntry { uint32_t ip; uint8_t mac[6]; bool valid; };
static NetArpEntry g_arp[8];
static int g_arp_rr = 0;

static void net_arp_learn(uint32_t ip, const uint8_t* mac) {
    if (!ip) return;
    for (int i = 0; i < 8; i++) if (g_arp[i].valid && g_arp[i].ip == ip) { net_cpy(g_arp[i].mac, mac, 6); return; }
    int s = -1;
    for (int i = 0; i < 8; i++) if (!g_arp[i].valid) { s = i; break; }
    if (s < 0) { s = g_arp_rr; g_arp_rr = (g_arp_rr + 1) & 7; }
    g_arp[s].ip = ip; net_cpy(g_arp[s].mac, mac, 6); g_arp[s].valid = true;
}
static bool net_arp_lookup(uint32_t ip, uint8_t* mac) {
    for (int i = 0; i < 8; i++) if (g_arp[i].valid && g_arp[i].ip == ip) { net_cpy(mac, g_arp[i].mac, 6); return true; }
    return false;
}

static uint8_t g_txf[1600];        // frames built by command-context senders
static uint8_t g_rxreply[1600];    // frames built while handling a received frame

static void net_send_arp(uint16_t op, const uint8_t* dst_mac, const uint8_t* tha, uint32_t tpa) {
    uint8_t f[64]; net_zero(f, sizeof(f));
    NetEth* e = (NetEth*)f; NetArp* a = (NetArp*)(f + 14);
    net_cpy(e->dst, dst_mac, 6); net_cpy(e->src, g_mac, 6); e->type = net_h16(0x0806);
    a->htype = net_h16(1); a->ptype = net_h16(0x0800); a->hlen = 6; a->plen = 4; a->op = net_h16(op);
    net_cpy(a->sha, g_mac, 6); net_put_ip(a->spa, g_ip);
    net_cpy(a->tha, tha, 6);   net_put_ip(a->tpa, tpa);
    net_send_frame(f, 42);
}

static uint16_t g_ip_id = 1;
// Build + send an IPv4 packet to a known MAC, using `buf` as scratch.
static bool net_ip_out(uint8_t* buf, const uint8_t* dmac, uint32_t src, uint32_t dst, uint8_t proto,
                       const uint8_t* payload, uint32_t plen) {
    if (plen > 1480) return false;
    NetEth* e = (NetEth*)buf; NetIp* ip = (NetIp*)(buf + 14);
    net_cpy(e->dst, dmac, 6); net_cpy(e->src, g_mac, 6); e->type = net_h16(0x0800);
    ip->vihl = 0x45; ip->tos = 0; ip->len = net_h16((uint16_t)(20 + plen)); ip->id = net_h16(g_ip_id++);
    ip->frag = 0; ip->ttl = 64; ip->proto = proto; ip->csum = 0;
    net_put_ip(ip->src, src); net_put_ip(ip->dst, dst);
    ip->csum = net_h16(net_csum(ip, 20));
    net_cpy(buf + 34, payload, plen);
    return net_send_frame(buf, 34 + plen);
}

// Resolve next-hop MAC (blocking, polls the NIC while waiting).
static bool net_resolve(uint32_t next, uint8_t* mac) {
    if (net_arp_lookup(next, mac)) return true;
    for (int attempt = 0; attempt < 3; attempt++) {
        static const uint8_t zero[6] = {0};
        net_send_arp(1, NET_BCAST, zero, next);
        uint64_t dl = net_deadline(400);
        while (!net_expired(dl)) {
            net_poll();
            if (net_arp_lookup(next, mac)) return true;
        }
    }
    return false;
}

static bool net_send_ip(uint32_t dst, uint8_t proto, const uint8_t* payload, uint32_t plen) {
    uint8_t mac[6];
    if (dst == 0xFFFFFFFFu || (g_ip && dst == (g_ip | ~g_mask))) net_cpy(mac, NET_BCAST, 6);
    else {
        if (!g_ip) return false;
        uint32_t next = ((dst & g_mask) == (g_ip & g_mask)) ? dst : g_gw;
        if (!next) return false;
        if (!net_resolve(next, mac)) return false;
    }
    return net_ip_out(g_txf, mac, g_ip, dst, proto, payload, plen);
}

// UDP ------------------------------------------------------------------------
static bool net_send_udp(uint32_t dst, uint16_t sport, uint16_t dport, const uint8_t* data, uint32_t len) {
    static uint8_t pkt[1500];
    if (len > 1400) return false;
    NetUdp* u = (NetUdp*)pkt;
    u->sport = net_h16(sport); u->dport = net_h16(dport); u->len = net_h16((uint16_t)(8 + len)); u->csum = 0;  // csum optional in IPv4
    net_cpy(pkt + 8, data, len);
    return net_send_ip(dst, 17, pkt, 8 + len);
}

// One-slot UDP receive mailbox, filled from net_input().
static volatile uint16_t g_udp_wait_port = 0;
static volatile bool     g_udp_got = false;
static uint8_t           g_udp_buf[1500];
static uint32_t          g_udp_len, g_udp_from;

static bool net_udp_wait(uint16_t port, uint32_t timeout_ms) {
    g_udp_got = false; g_udp_wait_port = port;
    uint64_t dl = net_deadline(timeout_ms);
    while (!g_udp_got && !net_expired(dl)) net_poll();
    g_udp_wait_port = 0;
    return g_udp_got;
}

// ICMP echo ------------------------------------------------------------------
static volatile bool g_ping_got = false;
static uint16_t g_ping_id = 0x4A31, g_ping_seq = 0;
static uint64_t g_ping_t0, g_ping_t1;
static uint32_t g_ping_from; static uint8_t g_ping_ttl;

// Frame input ----------------------------------------------------------------
static void net_input(const uint8_t* f, uint32_t len) {
    if (len < 14) return;
    const NetEth* e = (const NetEth*)f;
    uint16_t type = net_h16(e->type);

    if (type == 0x0806 && len >= 42) {                                   // ARP
        const NetArp* a = (const NetArp*)(f + 14);
        if (net_h16(a->htype) != 1 || net_h16(a->ptype) != 0x0800 || a->hlen != 6 || a->plen != 4) return;
        uint32_t spa = net_get_ip(a->spa), tpa = net_get_ip(a->tpa);
        uint16_t op = net_h16(a->op);
        if (op == 2) net_arp_learn(spa, a->sha);
        else if (op == 1 && g_ip && tpa == g_ip) {
            net_arp_learn(spa, a->sha);
            net_send_arp(2, a->sha, a->sha, spa);
        }
        return;
    }
    if (type != 0x0800 || len < 34) return;                              // IPv4 only beyond here

    const NetIp* ip = (const NetIp*)(f + 14);
    if ((ip->vihl >> 4) != 4) return;
    uint32_t ihl = (ip->vihl & 0xF) * 4, tot = net_h16(ip->len);
    if (ihl < 20 || tot < ihl || 14 + tot > len) return;
    if (net_csum(ip, ihl) != 0) return;
    if (net_h16(ip->frag) & 0x3FFF) return;                              // fragments not supported
    uint32_t src = net_get_ip(ip->src), dst = net_get_ip(ip->dst);
    // accept: unicast to us, broadcast, or anything while unconfigured (DHCP replies)
    if (g_ip && dst != g_ip && dst != 0xFFFFFFFFu && dst != (g_ip | ~g_mask)) return;
    const uint8_t* pl = f + 14 + ihl; uint32_t pll = tot - ihl;

    if (ip->proto == 1 && pll >= 8) {                                    // ICMP
        const NetIcmp* ic = (const NetIcmp*)pl;
        if (ic->type == 8 && g_ip && dst == g_ip) {                      // echo request -> reply
            static uint8_t rep[1500];
            if (pll > sizeof(rep)) return;
            net_cpy(rep, pl, pll);
            ((NetIcmp*)rep)->type = 0; ((NetIcmp*)rep)->csum = 0;
            ((NetIcmp*)rep)->csum = net_h16(net_csum(rep, pll));
            net_arp_learn(src, e->src);
            net_ip_out(g_rxreply, e->src, g_ip, src, 1, rep, pll);
        } else if (ic->type == 0 && net_h16(ic->id) == g_ping_id && net_h16(ic->seq) == g_ping_seq && !g_ping_got) {
            g_ping_t1 = net_rdtsc(); g_ping_from = src; g_ping_ttl = ip->ttl; g_ping_got = true;
        }
    } else if (ip->proto == 17 && pll >= 8) {                            // UDP
        const NetUdp* u = (const NetUdp*)pl;
        uint16_t dport = net_h16(u->dport), ulen = net_h16(u->len);
        if (ulen < 8 || ulen > pll) return;
        if (g_udp_wait_port && dport == g_udp_wait_port && !g_udp_got) {
            g_udp_len = ulen - 8; if (g_udp_len > sizeof(g_udp_buf)) g_udp_len = sizeof(g_udp_buf);
            net_cpy(g_udp_buf, pl + 8, g_udp_len);
            g_udp_from = src; g_udp_got = true;
        }
    }
}

// ──────────────────────────────────── DHCP ───────────────────────────────────
static bool net_dhcp_parse(uint32_t xid, uint8_t want_type, uint32_t* yi, uint32_t* srv,
                           uint32_t* mask, uint32_t* gw, uint32_t* dns) {
    if (g_udp_len < 240) return false;
    const uint8_t* b = g_udp_buf;
    if (b[0] != 2) return false;
    if (net_h32(*(const uint32_t*)(b + 4)) != xid) return false;
    if (!net_eq(b + 28, g_mac, 6)) return false;
    if (b[236] != 0x63 || b[237] != 0x82 || b[238] != 0x53 || b[239] != 0x63) return false;
    *yi = net_get_ip(b + 16);
    uint8_t type = 0;
    for (uint32_t i = 240; i < g_udp_len;) {
        uint8_t o = b[i++];
        if (o == 255) break;
        if (o == 0) continue;
        if (i >= g_udp_len) break;
        uint8_t l = b[i++];
        if (i + l > g_udp_len) break;
        if (o == 53 && l == 1) type = b[i];
        else if (o == 54 && l == 4) *srv = net_get_ip(b + i);
        else if (o == 1 && l == 4) *mask = net_get_ip(b + i);
        else if (o == 3 && l >= 4) *gw = net_get_ip(b + i);
        else if (o == 6 && l >= 4) *dns = net_get_ip(b + i);
        i += l;
    }
    return type == want_type;
}

static uint32_t g_dhcp_xid_ctr = 0;
static void net_dhcp_send(uint32_t xid, uint8_t type, uint32_t req_ip, uint32_t srv) {
    uint8_t p[320]; net_zero(p, sizeof(p));
    p[0] = 1; p[1] = 1; p[2] = 6;
    *(uint32_t*)(p + 4) = net_h32(xid);
    p[10] = 0x80;                                       // broadcast flag
    net_cpy(p + 28, g_mac, 6);
    p[236] = 0x63; p[237] = 0x82; p[238] = 0x53; p[239] = 0x63;
    uint32_t n = 240;
    p[n++] = 53; p[n++] = 1; p[n++] = type;
    p[n++] = 61; p[n++] = 7; p[n++] = 1; net_cpy(p + n, g_mac, 6); n += 6;
    if (type == 3) {
        p[n++] = 50; p[n++] = 4; net_put_ip(p + n, req_ip); n += 4;
        p[n++] = 54; p[n++] = 4; net_put_ip(p + n, srv);    n += 4;
    }
    p[n++] = 55; p[n++] = 3; p[n++] = 1; p[n++] = 3; p[n++] = 6;
    p[n++] = 255;
    uint32_t saved = g_ip; g_ip = 0;
    net_send_udp(0xFFFFFFFFu, 68, 67, p, 300);
    g_ip = saved;
}

static bool net_dhcp() {
    if (g_nic_type == NIC_NONE) return false;
    uint32_t saved_ip = g_ip; g_ip = 0;                 // unconfigured while negotiating
    uint32_t xid = (uint32_t)net_rdtsc() ^ (++g_dhcp_xid_ctr * 0x9E3779B1u);
    uint32_t yi = 0, srv = 0, mask = 0, gw = 0, dns = 0;
    bool ok = false;
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        net_dhcp_send(xid, 1, 0, 0);                    // DISCOVER
        g_udp_wait_port = 0;
        if (!net_udp_wait(68, 1500)) continue;
        if (!net_dhcp_parse(xid, 2, &yi, &srv, &mask, &gw, &dns)) continue;   // OFFER
        net_dhcp_send(xid, 3, yi, srv);                 // REQUEST
        uint64_t dl = net_deadline(1500);
        while (!net_expired(dl)) {
            if (!net_udp_wait(68, 200)) continue;
            uint32_t yi2 = 0, srv2 = 0, m2 = 0, g2 = 0, d2 = 0;
            if (net_dhcp_parse(xid, 5, &yi2, &srv2, &m2, &g2, &d2)) {       // ACK
                yi = yi2; if (m2) mask = m2; if (g2) gw = g2; if (d2) dns = d2;
                ok = true; break;
            }
        }
    }
    if (!ok) { g_ip = saved_ip; return false; }
    g_ip = yi; g_mask = mask ? mask : 0xFFFFFF00u; g_gw = gw; g_dns = dns ? dns : gw;
    g_net_configured = true;
    return true;
}

// ───────────────────────────────────── DNS ───────────────────────────────────
static bool net_parse_ip(const char* s, uint32_t* out) {
    uint32_t v = 0; int parts = 0;
    while (*s) {
        if (*s < '0' || *s > '9') return false;
        uint32_t n = 0; int digits = 0;
        while (*s >= '0' && *s <= '9') { n = n * 10 + (*s - '0'); s++; if (++digits > 3) return false; }
        if (n > 255) return false;
        v = (v << 8) | n; parts++;
        if (*s == '.') { s++; if (!*s) return false; } else if (*s) return false;
    }
    if (parts != 4) return false;
    *out = v; return true;
}

static uint16_t g_dns_id = 0x1234;
static bool net_dns_resolve(const char* name, uint32_t* ip_out) {
    if (!g_dns) return false;
    uint32_t nl = net_slen(name);
    if (nl == 0 || nl > 200) return false;
    uint8_t q[300]; net_zero(q, sizeof(q));
    uint16_t id = ++g_dns_id;
    q[0] = id >> 8; q[1] = id & 0xFF; q[2] = 0x01; q[5] = 1;           // RD=1, QDCOUNT=1
    uint32_t n = 12, lab = n++;
    uint8_t cnt = 0;
    for (uint32_t i = 0; i <= nl; i++) {
        char c = name[i];
        if (c == '.' || c == 0) {
            if (cnt == 0 || cnt > 63) return false;
            q[lab] = cnt; lab = n++; cnt = 0;
            if (c == 0) break;
        } else { q[n++] = (uint8_t)c; cnt++; }
    }
    q[lab] = 0;                                                         // root label
    n = lab + 1;
    q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 1;                     // QTYPE A, QCLASS IN

    uint16_t sport = 49152 + (id & 0x3FFF);
    for (int attempt = 0; attempt < 3; attempt++) {
        g_udp_got = false; g_udp_wait_port = sport;                     // arm BEFORE sending
        if (!net_send_udp(g_dns, sport, 53, q, n)) { g_udp_wait_port = 0; continue; }
        uint64_t dl = net_deadline(1500);
        while (!g_udp_got && !net_expired(dl)) net_poll();
        g_udp_wait_port = 0;
        if (!g_udp_got) continue;
        const uint8_t* r = g_udp_buf; uint32_t rl = g_udp_len;
        if (rl < 12 || (uint16_t)((r[0] << 8) | r[1]) != id || !(r[2] & 0x80) || (r[3] & 0x0F)) continue;
        uint32_t an = (r[6] << 8) | r[7], p = 12;
        for (uint32_t k = (r[4] << 8) | r[5]; k && p < rl; k--) {      // skip questions
            while (p < rl && r[p]) { if ((r[p] & 0xC0) == 0xC0) { p++; break; } p += r[p] + 1; }
            p += 1 + 4;
        }
        for (; an && p + 10 <= rl; an--) {
            while (p < rl && r[p]) { if ((r[p] & 0xC0) == 0xC0) { p++; break; } p += r[p] + 1; }
            p++;
            if (p + 10 > rl) break;
            uint16_t t = (r[p] << 8) | r[p + 1], rd = (r[p + 8] << 8) | r[p + 9];
            p += 10;
            if (p + rd > rl) break;
            if (t == 1 && rd == 4) { *ip_out = net_get_ip(r + p); return true; }
            p += rd;
        }
        return false;
    }
    return false;
}

static bool net_resolve_host(const char* h, uint32_t* ip) {
    if (net_parse_ip(h, ip)) return true;
    return net_dns_resolve(h, ip);
}

// ──────────────────────────────── ping (blocking) ────────────────────────────
static bool net_ping_once(uint32_t ip, uint32_t timeout_ms, uint32_t* rtt_x10) {
    uint8_t pkt[8 + 32];
    NetIcmp* ic = (NetIcmp*)pkt;
    ic->type = 8; ic->code = 0; ic->csum = 0;
    ic->id = net_h16(g_ping_id); g_ping_seq++; ic->seq = net_h16(g_ping_seq);
    for (int i = 0; i < 32; i++) pkt[8 + i] = 'a' + (i % 23);
    ic->csum = net_h16(net_csum(pkt, sizeof(pkt)));
    g_ping_got = false;
    uint8_t mac[6];
    uint32_t next = ((ip & g_mask) == (g_ip & g_mask)) ? ip : g_gw;
    if (!g_ip || !next || !net_resolve(next, mac)) return false;       // resolve first so RTT excludes ARP
    g_ping_t0 = net_rdtsc();
    if (!net_ip_out(g_txf, mac, g_ip, ip, 1, pkt, sizeof(pkt))) return false;
    uint64_t dl = net_deadline(timeout_ms);
    while (!g_ping_got && !net_expired(dl)) net_poll();
    if (!g_ping_got) return false;
    uint64_t d = g_ping_t1 - g_ping_t0;
    uint32_t div = g_net_tsc_per_ms >> 10; if (!div) div = 1;
    *rtt_x10 = (uint32_t)(d >> 10) * 10u / div;                         // avoids 64-bit division (no libgcc needed)
    return true;
}

// ───────────────────────────────── init + shell ──────────────────────────────
static void net_puts(const char* s) { console_print(s); }
static char* net_u32(char* o, uint32_t v) {
    char t[11]; int n = 0;
    do { t[n++] = '0' + v % 10; v /= 10; } while (v);
    while (n) *o++ = t[--n];
    *o = 0; return o;
}
static char* net_ipstr(char* o, uint32_t ip) {
    for (int i = 3; i >= 0; i--) { o = net_u32(o, (ip >> (i * 8)) & 0xFF); if (i) *o++ = '.'; }
    *o = 0; return o;
}
static char* net_macstr(char* o, const uint8_t* m) {
    const char* hx = "0123456789abcdef";
    for (int i = 0; i < 6; i++) { *o++ = hx[m[i] >> 4]; *o++ = hx[m[i] & 15]; if (i < 5) *o++ = ':'; }
    *o = 0; return o;
}
static char* net_cat(char* o, const char* s) { while (*s) *o++ = *s++; *o = 0; return o; }

static bool net_init(uint32_t tsc_per_ms) {
    if (tsc_per_ms > 1000) g_net_tsc_per_ms = tsc_per_ms;
    g_nic_type = NIC_NONE;
    for (uint16_t bus = 0; bus < 32 && g_nic_type == NIC_NONE; bus++) {
        for (uint8_t dev = 0; dev < 32 && g_nic_type == NIC_NONE; dev++) {
            uint32_t id0 = pci_read_config_dword(bus, dev, 0, 0);
            if ((id0 & 0xFFFF) == 0xFFFF) continue;
            uint8_t hdr = (pci_read_config_dword(bus, dev, 0, 0x0C) >> 16) & 0xFF;
            uint8_t nfn = (hdr & 0x80) ? 8 : 1;
            for (uint8_t fn = 0; fn < nfn; fn++) {
                uint32_t id = pci_read_config_dword(bus, dev, fn, 0);
                uint16_t ven = id & 0xFFFF, did = id >> 16;
                if (ven == 0xFFFF) continue;
                if (ven == 0x10EC && did == 0x8139) {
                    if (rtl_init(bus, dev, fn)) { g_nic_type = NIC_RTL8139; net_cat(g_nic_name, "Realtek RTL8139"); break; }
                } else if (ven == 0x8086 && (did == 0x100E || did == 0x100F || did == 0x10D3)) {
                    if (e1k_init(bus, dev, fn)) {
                        g_nic_type = NIC_E1000;
                        net_cat(g_nic_name, did == 0x10D3 ? "Intel 82574L (e1000e)" : "Intel e1000");
                        break;
                    }
                }
            }
        }
    }
    if (g_nic_type == NIC_NONE) return false;

    // Wait (bounded) for link, then try DHCP; fall back to QEMU user-net defaults.
    uint64_t dl = net_deadline(3000);
    while (!net_link_up() && !net_expired(dl)) net_pause();
    if (net_link_up() && net_dhcp()) return true;
    g_ip = 0x0A00020Fu; g_mask = 0xFFFFFF00u; g_gw = 0x0A000202u; g_dns = 0x0A000203u;   // 10.0.2.15 /24
    g_net_configured = false;
    return true;
}

static void net_show_config() {
    char b[160], *o;
    if (g_nic_type == NIC_NONE) { net_puts("No supported network card found (RTL8139 / e1000 / e1000e).\n"); return; }
    o = net_cat(b, "NIC : "); o = net_cat(o, g_nic_name); o = net_cat(o, net_link_up() ? "  [link up]\n" : "  [NO LINK]\n"); net_puts(b);
    o = net_cat(b, "MAC : "); o = net_macstr(o, g_mac); *o++ = '\n'; *o = 0; net_puts(b);
    o = net_cat(b, "IP  : "); o = net_ipstr(o, g_ip); o = net_cat(o, g_net_configured ? "  (DHCP)\n" : "  (static default)\n"); net_puts(b);
    o = net_cat(b, "Mask: "); o = net_ipstr(o, g_mask); *o++ = '\n'; *o = 0; net_puts(b);
    o = net_cat(b, "GW  : "); o = net_ipstr(o, g_gw); *o++ = '\n'; *o = 0; net_puts(b);
    o = net_cat(b, "DNS : "); o = net_ipstr(o, g_dns); *o++ = '\n'; *o = 0; net_puts(b);
}

static bool net_is_command(const char* c) {
    return net_seq(c, "ifconfig") || net_seq(c, "dhcp") || net_seq(c, "ping") ||
           net_seq(c, "nslookup") || net_seq(c, "arp");
}

// Split `args` (modifiable) into up to 4 whitespace-separated tokens.
static int net_tokens(char* a, char** tok, int max) {
    int n = 0;
    while (a && *a && n < max) {
        while (*a == ' ') a++;
        if (!*a) break;
        tok[n++] = a;
        while (*a && *a != ' ') a++;
        if (*a) *a++ = 0;
    }
    return n;
}

static void net_run_command(const char* cmd, char* args) {
    char* t[4]; int n = net_tokens(args, t, 4);
    char b[160], *o;
    if (g_nic_type == NIC_NONE && !net_seq(cmd, "ifconfig")) { net_puts("No network card detected.\n"); return; }

    if (net_seq(cmd, "ifconfig")) {
        if (n >= 2) {                                                   // ifconfig <ip> <mask> [gw]
            uint32_t ip, mask, gw = 0;
            if (!net_parse_ip(t[0], &ip) || !net_parse_ip(t[1], &mask) || (n >= 3 && !net_parse_ip(t[2], &gw))) {
                net_puts("Usage: ifconfig [<ip> <mask> [<gateway>]]\n"); return;
            }
            g_ip = ip; g_mask = mask; g_gw = gw; if (!g_dns) g_dns = gw; g_net_configured = false;
            for (int i = 0; i < 8; i++) g_arp[i].valid = false;
        }
        net_show_config();
    } else if (net_seq(cmd, "dhcp")) {
        net_puts("Requesting address via DHCP...\n");
        if (net_dhcp()) net_show_config(); else net_puts("DHCP failed (no reply). Use: ifconfig <ip> <mask> <gw>\n");
    } else if (net_seq(cmd, "arp")) {
        bool any = false;
        for (int i = 0; i < 8; i++) if (g_arp[i].valid) {
            o = net_ipstr(b, g_arp[i].ip); o = net_cat(o, "  at  "); o = net_macstr(o, g_arp[i].mac); *o++ = '\n'; *o = 0;
            net_puts(b); any = true;
        }
        if (!any) net_puts("ARP cache empty.\n");
    } else if (net_seq(cmd, "nslookup")) {
        if (n < 1) { net_puts("Usage: nslookup <hostname>\n"); return; }
        uint32_t ip;
        if (net_resolve_host(t[0], &ip)) { o = net_cat(b, t[0]); o = net_cat(o, " -> "); o = net_ipstr(o, ip); *o++ = '\n'; *o = 0; net_puts(b); }
        else net_puts("nslookup: could not resolve host (check DNS with ifconfig)\n");
    } else if (net_seq(cmd, "ping")) {
        if (n < 1) { net_puts("Usage: ping <ip|hostname> [count]\n"); return; }
        uint32_t ip;
        if (!net_resolve_host(t[0], &ip)) { net_puts("ping: unknown host\n"); return; }
        int count = 4;
        if (n >= 2) { count = 0; for (const char* c = t[1]; *c >= '0' && *c <= '9'; c++) count = count * 10 + (*c - '0'); if (count < 1) count = 1; if (count > 20) count = 20; }
        o = net_cat(b, "PING "); o = net_ipstr(o, ip); o = net_cat(o, "\n"); net_puts(b);
        int got = 0;
        for (int i = 0; i < count; i++) {
            uint32_t rtt;
            if (net_ping_once(ip, 2000, &rtt)) {
                got++;
                o = net_cat(b, "Reply from "); o = net_ipstr(o, g_ping_from); o = net_cat(o, ": ttl=");
                o = net_u32(o, g_ping_ttl); o = net_cat(o, " time="); o = net_u32(o, rtt / 10); *o++ = '.'; o = net_u32(o, rtt % 10);
                o = net_cat(o, " ms\n"); net_puts(b);
            } else net_puts("Request timed out.\n");
            uint64_t dl = net_deadline(300); while (!net_expired(dl)) net_poll();   // pace the pings
        }
        o = net_u32(b, got); o = net_cat(o, "/"); o = net_u32(o, count); o = net_cat(o, " replies received\n"); net_puts(b);
    }
}
