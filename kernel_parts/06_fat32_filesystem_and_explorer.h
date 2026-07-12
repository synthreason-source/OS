#pragma once
// 06_fat32_filesystem_and_explorer.h
// AHCI/disk driver, the FAT32 filesystem implementation, and
// FileExplorerWindow (the Explorer GUI).
// Extracted from kernel.cpp (original lines 2469-4347) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.




// =============================================================================
// SECTION 5: DISK DRIVER & FAT32 FILESYSTEM
// =============================================================================
#define SATA_SIG_ATA 0x00000101
#define PORT_CMD_ST 0x00000001
#define PORT_CMD_FRE 0x00000010
#define ATA_CMD_READ_DMA_EXT 0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35
#define HBA_PORT_CMD_CR 0x00008000
#define TFD_STS_BSY 0x80
#define TFD_STS_DRQ 0x08
#define FIS_TYPE_REG_H2D 0x27
#define DELETED_ENTRY 0xE5
#define ATTR_LONG_NAME 0x0F
#define ATTR_VOLUME_ID 0x08
#define ATTR_ARCHIVE 0x20
#define FAT_FREE_CLUSTER 0x00000000
#define FAT_END_OF_CHAIN 0x0FFFFFFF

// =============================================================================
// FILE EXPLORER WINDOW IMPLEMENTATION (New)
// =============================================================================



// Add these definitions near the other AHCI/FAT32 structs
typedef volatile struct {
    uint32_t clb;         // 0x00, command list base address, 1K-byte aligned
    uint32_t clbu;        // 0x04, command list base address upper 32 bits
    uint32_t fb;          // 0x08, FIS base address, 256-byte aligned
    uint32_t fbu;         // 0x0C, FIS base address upper 32 bits
    uint32_t is;          // 0x10, interrupt status
    uint32_t ie;          // 0x14, interrupt enable
    uint32_t cmd;         // 0x18, command and status
    uint32_t rsv0;        // 0x1C, Reserved
    uint32_t tfd;         // 0x20, task file data
    uint32_t sig;         // 0x24, signature
    uint32_t ssts;        // 0x28, SATA status (SCR0:SStatus)
    uint32_t sctl;        // 0x2C, SATA control (SCR2:SControl)
    uint32_t serr;        // 0x30, SATA error (SCR1:SError)
    uint32_t sact;        // 0x34, SATA active (SCR3:SActive)
    uint32_t ci;          // 0x38, command issue
    uint32_t sntf;        // 0x3C, SATA notification (SCR4:SNotification)
    uint32_t fbs;         // 0x40, FIS-based switching control
    uint32_t rsv1[11];    // 0x44 ~ 0x6F, Reserved
    uint32_t vendor[4];   // 0x70 ~ 0x7F, vendor specific
} HBA_PORT;

typedef volatile struct {
    uint32_t cap;         // 0x00, Host capability
    uint32_t ghc;         // 0x04, Global host control
    uint32_t is;          // 0x08, Interrupt status
    uint32_t pi;          // 0x0C, Port implemented
    uint32_t vs;          // 0x10, Version
    uint32_t ccc_ctl;     // 0x14, Command completion coalescing control
    uint32_t ccc_pts;     // 0x18, Command completion coalescing ports
    uint32_t em_loc;      // 0x1C, Enclosure management location
    uint32_t em_ctl;      // 0x20, Enclosure management control
    uint32_t cap2;        // 0x24, Host capabilities extended
    uint32_t bohc;        // 0x28, BIOS/OS handoff control and status
    uint8_t  rsv[0x60-0x2C];
    uint8_t  vendor[0x90-0x60]; // Vendor specific registers
    HBA_PORT ports[1];    // 0x90 ~ HBA memory mapped space, 1 ~ 32 ports
} HBA_MEM;


typedef struct { 
    uint8_t order; 
    uint16_t name1[5]; 
    uint8_t attr; 
    uint8_t type; 
    uint8_t checksum; 
    uint16_t name2[6]; 
    uint16_t fst_clus_lo; 
    uint16_t name3[2]; 
} __attribute__((packed)) fat_lfn_entry_t;

uint8_t lfn_checksum(const unsigned char *p_fname) {
    uint8_t sum = 0;
    for (int i = 11; i; i--) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + *p_fname++;
    }
    return sum;
}

static int g_ahci_port = -1; // Will store the first active port number
static int g_selected_port = -1; // User-selected disk port (-1 = use g_ahci_port)
static bool g_disk_unlocked = false;
static char g_disk_password_file[] = ".diskpass";
typedef struct { uint8_t cfl:5, a:1, w:1, p:1, r:1, b:1, c:1, res0:1; uint16_t prdtl; volatile uint32_t prdbc; uint64_t ctba; uint32_t res1[4]; } __attribute__((packed)) HBA_CMD_HEADER;
typedef struct { uint64_t dba; uint32_t res0; uint32_t dbc:22, res1:9, i:1; } __attribute__((packed)) HBA_PRDT_ENTRY;
typedef struct { uint8_t fis_type, pmport:4, res0:3, c:1, command, featurel; uint8_t lba0, lba1, lba2, device; uint8_t lba3, lba4, lba5, featureh; uint8_t countl, counth, icc, control; uint8_t res1[4]; } __attribute__((packed)) FIS_REG_H2D;
typedef struct { uint8_t jmp[3]; char oem[8]; uint16_t bytes_per_sec; uint8_t sec_per_clus; uint16_t rsvd_sec_cnt; uint8_t num_fats; uint16_t root_ent_cnt; uint16_t tot_sec16; uint8_t media; uint16_t fat_sz16; uint16_t sec_per_trk; uint16_t num_heads; uint32_t hidd_sec; uint32_t tot_sec32; uint32_t fat_sz32; uint16_t ext_flags; uint16_t fs_ver; uint32_t root_clus; uint16_t fs_info; uint16_t bk_boot_sec; uint8_t res[12]; uint8_t drv_num; uint8_t res1; uint8_t boot_sig; uint32_t vol_id; char vol_lab[11]; char fil_sys_type[8]; } __attribute__((packed)) fat32_bpb_t;


static uint64_t ahci_base = 0;
static HBA_CMD_HEADER* cmd_list;
static char* cmd_table_buffer;
// FIS receive buffer. Promoted from a disk_init() local to a global so
// ahci_port_setup() can program PxFB/PxFBU for any port, not just the
// one disk_init() auto-selected.
static char* g_ahci_fis_buffer = nullptr;
static fat32_bpb_t bpb;
static uint32_t fat_start_sector, data_start_sector;
static uint32_t current_directory_cluster = 0;
// Absolute disk LBA of the FAT32 partition's first sector (0 if the disk
// is a raw FAT32 image with no partition table — e.g. mkfat32.py output).
// Set by fat32_init when an MBR/GPT FAT32 partition is located; used by
// fat32_format so a format command on a partitioned bare-metal disk
// rewrites the partition's BPB instead of clobbering the MBR.
static uint64_t g_partition_lba = 0;

// --- Aligned Memory Allocator ---
void* alloc_aligned(size_t size, size_t alignment) {
    size_t offset = alignment - 1 + sizeof(void*);
    void* p1 = operator new(size + offset);
    if (p1 == nullptr) return nullptr;
    void** p2 = (void**)(((uintptr_t)p1 + offset) & ~(alignment - 1));
    p2[-1] = p1;
    return p2;
}

void free_aligned(void* ptr) {
    if (ptr == nullptr) return;
    operator delete(((void**)ptr)[-1]);
}
// Forward declarations: stop_cmd / start_cmd are defined further down
// (after read_write_sectors) but ahci_port_setup below needs them.
void stop_cmd(HBA_PORT* port);
void start_cmd(HBA_PORT* port);

// Program one AHCI port's command-list / FIS base registers and start
// its command engine. disk_init() did this inline for the single port
// it auto-selected; select_disk could then switch g_ahci_port to a
// DIFFERENT implemented port whose clb/fb were never programmed, so
// every subsequent command against it stalled (port->ci never cleared)
// and all I/O failed. Both callers now go through this so any port the
// kernel talks to is always fully initialised first.
//
// Returns true if the port has a device present and was set up.
static bool ahci_port_setup(int port_index) {
    if (!ahci_base || port_index < 0 || port_index >= 32) return false;
    if (!cmd_list || !cmd_table_buffer) return false;

    HBA_PORT* port = (HBA_PORT*)(ahci_base + 0x100 + (port_index * 0x80));

    uint8_t det = port->ssts & 0x0F;
    uint8_t ipm = (port->ssts >> 8) & 0x0F;
    if (det != 3 || ipm != 1) return false;     // no active device

    stop_cmd(port);

    port->clb  = (uint32_t)(uintptr_t)cmd_list;
    port->clbu = (uint32_t)(((uint64_t)(uintptr_t)cmd_list) >> 32);
    port->fb   = (uint32_t)(uintptr_t)g_ahci_fis_buffer;
    port->fbu  = (uint32_t)(((uint64_t)(uintptr_t)g_ahci_fis_buffer) >> 32);

    port->serr = 0xFFFFFFFF;
    port->is   = 0xFFFFFFFF;                    // clear stale interrupts

    start_cmd(port);
    return true;
}

void cmd_list_and_select_disk(const char* arg) {
    // List all detected AHCI ports
    if (!ahci_base) {
        wm.print_to_focused("No AHCI controller found.\n");
        return;
    }

    uint32_t ports_implemented = *(volatile uint32_t*)(ahci_base + 0x0C);
    char msg[128];

    if (!arg || arg[0] == '\0') {
        // No argument: list available disks
        wm.print_to_focused("Available disks:\n");
        bool found = false;
        for (int i = 0; i < 32; i++) {
            if (!(ports_implemented & (1 << i))) continue;
            HBA_PORT* port = (HBA_PORT*)(ahci_base + 0x100 + (i * 0x80));
            uint8_t det = port->ssts & 0x0F;
            uint8_t ipm = (port->ssts >> 8) & 0x0F;
            if (det != 3 || ipm != 1) continue;

            int active = (i == g_ahci_port) ? 1 : 0;
            int selected = (i == g_selected_port || (g_selected_port == -1 && i == g_ahci_port)) ? 1 : 0;

            snprintf(msg, 128, "  Port %d: %s%s\n",
                     i,
                     active  ? "[AHCI] " : "",
                     selected ? "<-- selected" : "");
            wm.print_to_focused(msg);
            found = true;
        }
        if (!found) wm.print_to_focused("  (no drives detected)\n");
        wm.print_to_focused("Usage: select_disk <port>\n");
        return;
    }

    // Argument given: select that port
    int requested = simple_atoi(arg);
    if (!(ports_implemented & (1 << requested))) {
        snprintf(msg, 128, "Port %d not implemented.\n", requested);
        wm.print_to_focused(msg);
        return;
    }

    HBA_PORT* port = (HBA_PORT*)(ahci_base + 0x100 + (requested * 0x80));
    uint8_t det = port->ssts & 0x0F;
    uint8_t ipm = (port->ssts >> 8) & 0x0F;
    if (det != 3 || ipm != 1) {
        snprintf(msg, 128, "Port %d has no active drive (det=%d ipm=%d).\n", requested, det, ipm);
        wm.print_to_focused(msg);
        return;
    }

    // Switch disk. Program the target port's command-list / FIS base
    // and start its command engine BEFORE issuing any I/O to it —
    // disk_init() only set up the port it auto-selected, so without this
    // a switch to any other port left it uninitialised and every read
    // or write against it stalled.
    if (!ahci_port_setup(requested)) {
        snprintf(msg, 128, "Port %d setup failed.\n", requested);
        wm.print_to_focused(msg);
        return;
    }
    g_selected_port = requested;
    g_ahci_port     = requested;           // redirect all I/O immediately

    // Re-initialise FAT32 on the new disk
    bool ok = fat32_init();
    snprintf(msg, 128, "Switched to disk port %d. FAT32: %s\n",
             requested, ok ? "OK" : "not found / failed");
    wm.print_to_focused(msg);

    if (ok) wm.load_desktop_items();      // refresh desktop icons from new disk
}int read_write_sectors(int port_num, uint64_t lba, uint16_t count,
                       bool write, void* buffer) {
    if (port_num < 0 || port_num >= 32 || !ahci_base) return -1;

    HBA_PORT* port = (HBA_PORT*)(ahci_base + 0x100 + (port_num * 0x80));
    port->is = 0xFFFFFFFF;

    uint32_t slots = (port->sact | port->ci);
    int slot = -1;
    for (int i = 0; i < 32; i++) {
        if ((slots & (1 << i)) == 0) { slot = i; break; }
    }
    if (slot == -1) return -1;

    // --- WRITE PATH: encrypt a copy before sending to disk ---
    uint8_t* enc_buf = nullptr;
    void*    io_buf  = buffer;

    if (write && g_fs_encryption_enabled) {
        enc_buf = new uint8_t[count * SECTOR_SIZE];
        if (!enc_buf) return -1;
        memcpy(enc_buf, buffer, count * SECTOR_SIZE);
        for (int s = 0; s < count; s++) {
            xor_sector(enc_buf + s * SECTOR_SIZE, lba + s);
        }
        io_buf = enc_buf;
    }

    HBA_CMD_HEADER* cmd_header = &cmd_list[slot];
    cmd_header->cfl    = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmd_header->w      = write;
    cmd_header->prdtl  = 1;

    uintptr_t       cmd_table_addr = (uintptr_t)cmd_header->ctba;
    FIS_REG_H2D*    cmd_fis        = (FIS_REG_H2D*)(cmd_table_addr);
    HBA_PRDT_ENTRY* prdt           = (HBA_PRDT_ENTRY*)(cmd_table_addr + 128);

    prdt->dba = (uint64_t)(uintptr_t)io_buf;
    prdt->dbc = (count * SECTOR_SIZE) - 1;
    prdt->i   = 0;

    memset(cmd_fis, 0, sizeof(FIS_REG_H2D));
    cmd_fis->fis_type = FIS_TYPE_REG_H2D;
    cmd_fis->c        = 1;
    cmd_fis->command  = write ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT;
    cmd_fis->lba0     = (uint8_t)lba;
    cmd_fis->lba1     = (uint8_t)(lba >> 8);
    cmd_fis->lba2     = (uint8_t)(lba >> 16);
    cmd_fis->device   = 1 << 6;
    cmd_fis->lba3     = (uint8_t)(lba >> 24);
    cmd_fis->lba4     = (uint8_t)(lba >> 32);
    cmd_fis->lba5     = (uint8_t)(lba >> 40);
    cmd_fis->countl   = count & 0xFF;
    cmd_fis->counth   = (count >> 8) & 0xFF;

    while (port->tfd & (TFD_STS_BSY | TFD_STS_DRQ));
    port->ci = (1 << slot);

    // Wait for the command slot to clear. The previous budget (100000
    // tight-loop iterations) was far too small: a real DMA write —
    // especially the first WRITE_DMA_EXT after the command engine has
    // been idle, e.g. the boot-sector write in formatfs — routinely did
    // not finish within it, so the function returned -1 and the format
    // reported "Failed to write new boot sector". Reads happened to fit
    // the old budget often enough to look reliable. Use a much larger
    // budget and ALSO bail out early on a real task-file error rather
    // than relying on the spin count alone.
    const long IO_TIMEOUT = 200000000L;   // generous; covers slow writes
    long spin = 0;
    bool timed_out = false;
    while (true) {
        if ((port->ci & (1 << slot)) == 0) break;   // command finished
        if (port->is & (1 << 30)) break;            // TFES: task-file error
        if (++spin >= IO_TIMEOUT) { timed_out = true; break; }
    }

    if (enc_buf) { delete[] enc_buf; enc_buf = nullptr; }

    if (timed_out) return -1;
    // Real error if the TFES interrupt fired OR the task-file register
    // reports ERR (bit 0). PxTFD.STS bit0 = ERR; checking it catches a
    // device-rejected command even when PxIS bit 30 was already cleared.
    if (port->is & (1 << 30)) return -1;
    if (port->tfd & 0x01)     return -1;

    // --- READ PATH: decrypt in place after receiving from disk ---
    if (!write && g_fs_encryption_enabled) {
        for (int s = 0; s < count; s++) {
            xor_sector((uint8_t*)buffer + s * SECTOR_SIZE, lba + s);
        }
    }

    return 0;
}
void stop_cmd(HBA_PORT *port) {
    port->cmd &= ~0x0001; // Clear ST (Start)
    port->cmd &= ~0x0010; // Clear FRE (FIS Receive Enable)

    // Wait until Command List Running (CR) and FIS Receive Running (FR) are cleared
    while(port->cmd & 0x8000 || port->cmd & 0x4000);
}

// Helper to start a port's command engine
void start_cmd(HBA_PORT *port) {
    // Wait until Command List Running (CR) is cleared
    while(port->cmd & 0x8000);

    port->cmd |= 0x0010; // Set FRE (FIS Receive Enable)
    port->cmd |= 0x0001; // Set ST (Start)
}
void disk_init() {
    // ─────────────────────────────────────────────────────────────────────
    // Find the AHCI controller on PCI.
    //
    // Why the previous one-liner missed real hardware:
    //   1. It only checked function 0. On every Intel chipset the SATA
    //      controller lives at 00:1F.2 — bus 0, dev 0x1F, function 2.
    //      QEMU and VMware happened to put theirs on function 0, which
    //      is why those worked while bare metal never did.
    //   2. It only matched class/subclass 0x0106 (SATA/AHCI). Many
    //      consumer machines (Dell, HP, Lenovo) ship with BIOS default
    //      "RAID On", in which case the same hardware reports 0x0104
    //      (RAID) while still being AHCI-compatible underneath. Some
    //      Marvell/ASMedia add-in cards report 0x0180 ("Other").
    //   3. It scanned only 8 buses. Cheap to widen.
    // ─────────────────────────────────────────────────────────────────────
    ahci_base = 0;
    uint16_t found_bus = 0; uint8_t found_dev = 0; uint8_t found_fn = 0;
    bool found = false;

    for (uint16_t bus = 0; bus < 256 && !found; bus++) {
        for (uint8_t dev = 0; dev < 32 && !found; dev++) {
            for (uint8_t fn = 0; fn < 8 && !found; fn++) {
                uint32_t vd = pci_read_config_dword(bus, dev, fn, 0x00);
                if ((vd & 0xFFFFu) == 0xFFFFu) continue;   // empty slot

                uint32_t cc = pci_read_config_dword(bus, dev, fn, 0x08);
                uint8_t base_class = (cc >> 24) & 0xFFu;
                uint8_t subclass   = (cc >> 16) & 0xFFu;

                if (base_class != 0x01) continue;          // not mass storage
                // Accept SATA(6), RAID(4), and Other(0x80).
                if (subclass != 0x06 && subclass != 0x04 && subclass != 0x80)
                    continue;

                // BAR5 = ABAR (AHCI Base Memory Register).
                uint32_t bar5 = pci_read_config_dword(bus, dev, fn, 0x24);
                if (bar5 & 1u) continue;                    // I/O BAR, not MMIO
                uint32_t abar = bar5 & 0xFFFFFFF0u;
                if (abar < 0x1000u) continue;               // empty / unmapped

                ahci_base = abar;
                found_bus = bus; found_dev = dev; found_fn = fn;
                found = true;
            }
        }
    }

    if (!ahci_base) {
        wm.print_to_focused("AHCI: no controller found on any PCI bus.\n");
        wm.print_to_focused("  On bare metal: set SATA mode to AHCI in BIOS\n");
        wm.print_to_focused("  (look for 'SATA Operation' / 'SATA Mode Selection').\n");
        return;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Enable bus-master + memory-space decode in the PCI command register.
    // Firmware *usually* leaves these on for the boot device, but UEFI
    // platforms that booted via NVMe/USB sometimes leave the SATA
    // controller un-enabled.
    // ─────────────────────────────────────────────────────────────────────
    {
        uint32_t cmd = pci_read_config_dword(found_bus, found_dev, found_fn, 0x04);
        uint32_t addr_reg = 0x80000000u
                          | ((uint32_t)found_bus << 16)
                          | ((uint32_t)found_dev << 11)
                          | ((uint32_t)found_fn  <<  8)
                          | 0x04u;
        outl(0xCF8, addr_reg);
        outl(0xCFC, cmd | 0x06u);    // bit 1 = memory, bit 2 = bus master
    }

    // ─────────────────────────────────────────────────────────────────────
    // Engage AHCI mode (GHC.AE = bit 31 of Global Host Control at MMIO
    // offset 0x04). Needed when the HBA came up in legacy / IDE-compat
    // mode, which is common on Intel chipsets where the firmware didn't
    // explicitly flip the mode-select bit during POST.
    // ─────────────────────────────────────────────────────────────────────
    {
        volatile uint32_t* ghc = (volatile uint32_t*)(uintptr_t)(ahci_base + 0x04);
        *ghc |= (1u << 31);                                  // AE
        // Brief spin so the HBA acknowledges before we read PxSSTS / PI.
        for (volatile uint32_t i = 0; i < 100000u; i++);
    }

    {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "AHCI: found at %02x:%02x.%x  ABAR=0x%08x\n",
                 (unsigned)found_bus, (unsigned)found_dev, (unsigned)found_fn,
                 (unsigned)ahci_base);
        wm.print_to_focused(msg);
    }

    // ── Allocate command list / FIS / cmd-table buffers ─────────────────
    cmd_list = (HBA_CMD_HEADER*)alloc_aligned(32 * sizeof(HBA_CMD_HEADER), 1024);
    cmd_table_buffer = (char*)alloc_aligned(32 * 256, 128);
    g_ahci_fis_buffer = (char*)alloc_aligned(256, 256);

    if (!cmd_list || !cmd_table_buffer || !g_ahci_fis_buffer) return;

    for(int k=0; k<32; ++k) {
        cmd_list[k].ctba = (uint64_t)(uintptr_t)(cmd_table_buffer + (k * 256));
    }

    uint32_t ports_implemented = *(volatile uint32_t*)(uintptr_t)(ahci_base + 0x0C);

    // Auto-select a port. Two passes so a SATA disk on port 1 is preferred
    // over an ATAPI CD-ROM on port 0 (which is exactly the QEMU layout in
    // compile.md — `bus=ahci.0` for the CD, `bus=ahci.1` for the HDD).
    //
    // PxSIG (port offset 0x24) tells us what kind of device is attached:
    //   0x00000101 = SATA disk
    //   0xEB140101 = SATAPI / ATAPI (CD-ROM, DVD, etc.)
    //   0xC33C0101 = enclosure-management bridge
    //   0x96690101 = port multiplier
    //
    // Pass 1: claim the first SATA disk.
    // Pass 2: fall back to anything else (so we don't strand a CD-only
    // configuration with no port selected at all).
    auto try_select = [&](bool sata_only) -> bool {
        for (int i = 0; i < 32; i++) {
            if (!(ports_implemented & (1u << i))) continue;
            volatile HBA_PORT* p = (volatile HBA_PORT*)(uintptr_t)
                                    (ahci_base + 0x100 + (i * 0x80));
            uint32_t sig = p->sig;
            if (sata_only && sig != 0x00000101u) continue;
            if (ahci_port_setup(i)) {
                g_ahci_port = i;
                char msg[80];
                const char* kind = (sig == 0x00000101u) ? "SATA disk"
                                 : (sig == 0xEB140101u) ? "ATAPI (CD/DVD)"
                                 : "unknown";
                snprintf(msg, sizeof(msg),
                         "AHCI: port %d active (%s).\n", i, kind);
                wm.print_to_focused(msg);
                return true;
            }
        }
        return false;
    };
    if (try_select(true))  return;     // first SATA disk
    if (try_select(false)) return;     // fall back to anything
    wm.print_to_focused("AHCI: controller found but no active drive on any port.\n");
}bool fat32_init() {
    if (!ahci_base) return false;

    // Boot sector is always plaintext — read it raw regardless of crypto state
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;

    char* buffer = new char[SECTOR_SIZE];
    if (!buffer) {
        g_fs_encryption_enabled = was_enabled;
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Sector 0 can be one of three things on a real disk:
    //   (a) Raw FAT32 boot sector — what mkfat32.py produces for QEMU/VMware.
    //       Identifiable by "FAT32   " string at offset 82.
    //   (b) Classic MBR — first 446 bytes are bootstrap, then a 4-entry
    //       partition table at offset 446, then signature 0x55 0xAA at 510.
    //       FAT32 partition types are 0x0B, 0x0C, 0x1B, 0x1C.
    //   (c) GPT protective MBR — signature 0x55 0xAA at 510, but the
    //       partition table contains exactly one entry of type 0xEE
    //       spanning the disk; the real GPT header lives at LBA 1, with
    //       128-byte entries starting at LBA 2 (or wherever the header
    //       says).
    //
    // We resolve the FAT32 partition's start LBA into partition_lba.
    // fat_start_sector / data_start_sector then carry absolute disk LBAs,
    // so cluster_to_lba and read_fat_entry keep working unchanged.
    // ─────────────────────────────────────────────────────────────────────
    if (read_write_sectors(g_ahci_port, 0, 1, false, buffer) != 0) {
        g_fs_encryption_enabled = was_enabled;
        delete[] buffer;
        return false;
    }

    uint64_t partition_lba = 0;
    bool     found_fat32   = false;
    bool     sector0_is_fat32 = (strncmp(buffer + 82, "FAT32", 5) == 0);
    bool     has_mbr_sig =
        ((uint8_t)buffer[510] == 0x55 && (uint8_t)buffer[511] == 0xAA);

    if (sector0_is_fat32) {
        // (a) Raw image. Sector 0 itself is the BPB. partition_lba stays 0.
        found_fat32 = true;
    } else if (has_mbr_sig) {
        // Detect GPT protective MBR vs classic MBR.
        bool is_protective_mbr = false;
        for (int i = 0; i < 4; i++) {
            if ((uint8_t)buffer[446 + i*16 + 4] == 0xEE) {
                is_protective_mbr = true;
                break;
            }
        }

        if (is_protective_mbr) {
            // ───── (c) GPT path ────────────────────────────────────────
            // Read GPT header at LBA 1. Header layout (only the fields
            // we need): signature "EFI PART" at offset 0, partition-
            // entry LBA at offset 72 (8 bytes), num_entries at offset 80
            // (4 bytes), entry_size at offset 84 (4 bytes).
            char* gpt_hdr = new char[SECTOR_SIZE];
            if (gpt_hdr &&
                read_write_sectors(g_ahci_port, 1, 1, false, gpt_hdr) == 0 &&
                strncmp(gpt_hdr, "EFI PART", 8) == 0)
            {
                uint64_t pe_lba   = *(uint64_t*)(gpt_hdr + 72);
                uint32_t pe_count = *(uint32_t*)(gpt_hdr + 80);
                uint32_t pe_size  = *(uint32_t*)(gpt_hdr + 84);

                // Sanity-cap; GPT spec mandates >= 128 entries, 128-byte size.
                if (pe_count > 256) pe_count = 256;
                if (pe_size  < 128 || pe_size > SECTOR_SIZE) pe_size = 128;

                uint32_t entries_per_sector = SECTOR_SIZE / pe_size;
                uint32_t sectors_to_read    =
                    (pe_count + entries_per_sector - 1) / entries_per_sector;

                char* entries = new char[SECTOR_SIZE];
                for (uint32_t s = 0;
                     entries && s < sectors_to_read && !found_fat32; s++)
                {
                    if (read_write_sectors(g_ahci_port, pe_lba + s, 1,
                                           false, entries) != 0) break;
                    for (uint32_t e = 0;
                         e < entries_per_sector && !found_fat32; e++)
                    {
                        char*    ent       = entries + e * pe_size;
                        uint64_t first_lba = *(uint64_t*)(ent + 32);
                        if (first_lba == 0) continue;   // empty slot

                        // Don't filter on type-GUID — just probe each
                        // partition's first sector for the FAT32 string.
                        // Avoids hard-coding the Microsoft Basic Data
                        // GUID (which most FAT32 ESP/data partitions
                        // use, but some installers vary).
                        if (read_write_sectors(g_ahci_port, first_lba, 1,
                                               false, buffer) != 0) continue;
                        if (strncmp(buffer + 82, "FAT32", 5) == 0) {
                            partition_lba = first_lba;
                            found_fat32   = true;
                        }
                    }
                }
                delete[] entries;
            }
            delete[] gpt_hdr;
        } else {
            // ───── (b) Classic MBR path ────────────────────────────────
            // Walk the 4-entry partition table. Take the first FAT32
            // partition whose boot sector verifies.
            for (int i = 0; i < 4 && !found_fat32; i++) {
                uint8_t* part = (uint8_t*)(buffer + 446 + i * 16);
                uint8_t  type = part[4];
                if (type != 0x0B && type != 0x0C &&
                    type != 0x1B && type != 0x1C) continue;

                uint64_t lba = (uint64_t) part[8]         |
                               ((uint64_t)part[9]  <<  8) |
                               ((uint64_t)part[10] << 16) |
                               ((uint64_t)part[11] << 24);
                if (lba == 0) continue;

                if (read_write_sectors(g_ahci_port, lba, 1, false, buffer) == 0
                    && strncmp(buffer + 82, "FAT32", 5) == 0)
                {
                    partition_lba = lba;
                    found_fat32   = true;
                }
            }
        }
    }

    g_fs_encryption_enabled = was_enabled;

    if (!found_fat32) {
        delete[] buffer;
        current_directory_cluster = 0;
        if (sector0_is_fat32) {
            // Shouldn't happen — we already set found_fat32 above.
        } else if (has_mbr_sig) {
            wm.print_to_focused("FAT32: partition table present, but no FAT32 partition.\n");
            wm.print_to_focused("  Create one (MBR type 0x0C, or GPT 'Microsoft Basic Data').\n");
        } else {
            wm.print_to_focused("FAT32: disk has no partition table and no FAT32 BPB.\n");
            wm.print_to_focused("  Either format the disk or write a raw FAT32 image.\n");
        }
        return false;
    }

    // `buffer` now holds the FAT32 BPB (sector 0 directly, or the
    // partition's first sector via MBR/GPT lookup).
    memcpy(&bpb, buffer, sizeof(bpb));
    delete[] buffer;

    if (strncmp(bpb.fil_sys_type, "FAT32", 5) != 0) {
        // Defensive: shouldn't trigger because we verified above.
        current_directory_cluster = 0;
        return false;
    }

    // fat_start_sector / data_start_sector hold ABSOLUTE disk LBAs.
    // partition_lba == 0 for the raw-image case, so QEMU/VMware
    // behaviour is byte-for-byte unchanged.
    g_partition_lba   = partition_lba;
    fat_start_sector  = partition_lba + bpb.rsvd_sec_cnt;
    data_start_sector = fat_start_sector + (bpb.num_fats * bpb.fat_sz32);
    current_directory_cluster = bpb.root_clus;

    if (partition_lba) {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "FAT32: partition @ LBA %u, root_clus %u\n",
                 (unsigned)partition_lba, (unsigned)current_directory_cluster);
        wm.print_to_focused(msg);
    }
    return true;
}
uint64_t cluster_to_lba(uint32_t cluster) {
  return (uint64_t)(cluster - 2) * bpb.sec_per_clus + data_start_sector;
}

// Number of clusters in the FAT32 filesystem, computed entirely from BPB
// fields so it is independent of where on the disk the partition lives.
// The old formula `bpb.tot_sec32 - data_start_sector` worked only when
// data_start_sector was partition-relative; once we support MBR/GPT,
// data_start_sector holds the absolute disk LBA and the subtraction
// underflows. This helper sidesteps the issue.
static inline uint32_t fat32_data_sectors() {
    uint32_t reserved = bpb.rsvd_sec_cnt;
    uint32_t fats     = bpb.num_fats * bpb.fat_sz32;
    uint32_t fs_total = bpb.tot_sec32;
    if (fs_total <= reserved + fats) return 0;
    return fs_total - reserved - fats;
}
static inline uint32_t fat32_max_clusters() {
    if (bpb.sec_per_clus == 0) return 0;
    return fat32_data_sectors() / bpb.sec_per_clus + 2;
}void to_83_format(const char* filename, char* out) { memset(out, ' ', 11); int i = 0, j = 0; while (filename[i] && filename[i] != '.' && j < 8) { out[j++] = (filename[i] >= 'a' && filename[i] <= 'z') ? (filename[i]-32) : filename[i]; i++; } if(filename[i] == '.') i++; j=8; while(filename[i] && j<11) { out[j++] = (filename[i] >= 'a' && filename[i] <= 'z') ? (filename[i]-32) : filename[i]; i++; } }

void from_83_format(const char* fat_name, char* out) {
    int i, j = 0;
    // Process the name part (before the extension)
    for (i = 0; i < 8 && fat_name[i] != ' '; i++) {
        // Only convert uppercase letters to lowercase
        out[j++] = (fat_name[i] >= 'A' && fat_name[i] <= 'Z') ? fat_name[i] + 32 : fat_name[i];
    }
    
    // Process the extension part, if it exists
    if (fat_name[8] != ' ') {
        out[j++] = '.';
        for (i = 8; i < 11 && fat_name[i] != ' '; i++) {
            // Only convert uppercase letters to lowercase
            out[j++] = (fat_name[i] >= 'A' && fat_name[i] <= 'Z') ? fat_name[i] + 32 : fat_name[i];
        }
    }
    out[j] = '\0';
}

void fat32_get_fne_from_entry(fat_dir_entry_t* entry, char* out) {
    from_83_format(entry->name, out);
}

uint32_t read_fat_entry(uint32_t cluster) {
    uint8_t* fat_sector = new uint8_t[SECTOR_SIZE];
    uint32_t fat_offset = cluster * 4;

    read_write_sectors(g_ahci_port, fat_start_sector + (fat_offset / SECTOR_SIZE), 1, false, fat_sector);
    uint32_t value = *(uint32_t*)(fat_sector + (fat_offset % SECTOR_SIZE)) & 0x0FFFFFFF;
    delete[] fat_sector;
    return value;
}

bool write_fat_entry(uint32_t cluster, uint32_t value) {
    uint8_t* fat_sector = new uint8_t[SECTOR_SIZE];
    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector_index = fat_offset / SECTOR_SIZE;
    uint32_t sector_num = fat_start_sector + fat_sector_index;

    read_write_sectors(g_ahci_port, sector_num, 1, false, fat_sector);
    *(uint32_t*)(fat_sector + (fat_offset % SECTOR_SIZE)) =
        (*(uint32_t*)(fat_sector + (fat_offset % SECTOR_SIZE)) & 0xF0000000) |
        (value & 0x0FFFFFFF);

    bool success = read_write_sectors(g_ahci_port, sector_num, 1, true, fat_sector) == 0;

    // ─────────────────────────────────────────────────────────────────────
    // Mirror to FAT2. The FAT32 spec says: if BPB_ExtFlags bit 7 is clear
    // (the default), the FAT is mirrored — every update must hit FAT1 AND
    // FAT2. Windows CHKDSK and Linux dosfsck both treat FAT1/FAT2 mismatch
    // as filesystem corruption and may "repair" by overwriting the live
    // FAT from the stale one. The old code wrote only FAT1, guaranteeing
    // every file created by this OS looked corrupted to any other OS.
    //
    // If ext_flags bit 7 is set, only the FAT specified by bits 0-3 is
    // active; honour that and skip the mirror.
    // ─────────────────────────────────────────────────────────────────────
    bool mirror_fats = (bpb.ext_flags & 0x0080) == 0;
    if (success && mirror_fats && bpb.num_fats >= 2) {
        uint32_t fat2_sector_num = fat_start_sector + bpb.fat_sz32 + fat_sector_index;
        success = read_write_sectors(g_ahci_port, fat2_sector_num, 1, true, fat_sector) == 0;
    }

    delete[] fat_sector;
    return success;
}

uint32_t find_free_cluster() {
    uint32_t max_clusters = fat32_max_clusters();
    for (uint32_t i = 2; i < max_clusters; i++) if (read_fat_entry(i) == FAT_FREE_CLUSTER) return i;
    return 0;
}

uint32_t allocate_cluster() {
    uint32_t free_cluster = find_free_cluster();
    if (free_cluster != 0) write_fat_entry(free_cluster, FAT_END_OF_CHAIN);
    return free_cluster;
}

void free_cluster_chain(uint32_t start_cluster) {
    uint32_t current = start_cluster;
    while(current < FAT_END_OF_CHAIN) { uint32_t next = read_fat_entry(current); write_fat_entry(current, FAT_FREE_CLUSTER); current = next; }
}

// Hinted free-cluster scan: starts from `start_from` instead of cluster 2.
// allocate_cluster_chain uses this to avoid the O(N^2) cost of the original
// "always scan from cluster 2" loop — that read the same FAT sectors over
// and over (millions of redundant reads for a 1 MB file at 512-byte
// clusters). Falls back to a full scan if nothing was found above the hint.
static uint32_t find_free_cluster_hinted(uint32_t start_from) {
    uint32_t max_clusters = fat32_max_clusters();
    if (start_from < 2) start_from = 2;
    for (uint32_t i = start_from; i < max_clusters; i++)
        if (read_fat_entry(i) == FAT_FREE_CLUSTER) return i;
    for (uint32_t i = 2; i < start_from && i < max_clusters; i++)
        if (read_fat_entry(i) == FAT_FREE_CLUSTER) return i;
    return 0;
}

uint32_t allocate_cluster_chain(uint32_t num_clusters) {
    if(num_clusters == 0) return 0;
    // Find the first free cluster (full scan, once).
    uint32_t first = allocate_cluster();
    if(first == 0) return 0;
    uint32_t current = first;
    // For the rest of the chain, scan FORWARD from the last cluster we
    // grabbed — on a freshly-formatted disk the next free cluster is
    // almost always current+1, which costs one FAT read per allocation
    // instead of (number-allocated-so-far) FAT reads.
    for(uint32_t i = 1; i < num_clusters; i++) {
        uint32_t next = find_free_cluster_hinted(current + 1);
        if(next == 0) { free_cluster_chain(first); return 0; }
        write_fat_entry(next,    FAT_END_OF_CHAIN); // mark allocated
        write_fat_entry(current, next);             // link previous → next
        current = next;
    }
    return first;
}

bool read_data_from_clusters(uint32_t start_cluster, void* data, uint32_t size) {
    if (size == 0) return true;
    uint8_t* data_ptr = (uint8_t*)data;
    uint32_t remaining = size;
    uint32_t current_cluster = start_cluster;
    uint32_t cluster_size = bpb.sec_per_clus * SECTOR_SIZE;

    while (current_cluster >= 2 && current_cluster < FAT_END_OF_CHAIN && remaining > 0) {
        uint32_t to_read = (remaining > cluster_size) ? cluster_size : remaining;
        uint8_t* cluster_buf = new uint8_t[cluster_size];
        memset(cluster_buf, 0, cluster_size); // Clear buffer
        if(read_write_sectors(g_ahci_port, cluster_to_lba(current_cluster), bpb.sec_per_clus, false, cluster_buf) != 0) { 
            delete[] cluster_buf; 
            return false; 
        }
        memcpy(data_ptr, cluster_buf, to_read);
        delete[] cluster_buf;
        data_ptr += to_read;
        remaining -= to_read;
        if (remaining > 0) current_cluster = read_fat_entry(current_cluster);
        else break;
    }
    return true;
}

bool write_data_to_clusters(uint32_t start_cluster, const void* data, uint32_t size) {
    if (size == 0) return true;
    const uint8_t* data_ptr = (const uint8_t*)data;
    uint32_t remaining = size;
    uint32_t current_cluster = start_cluster;
    uint32_t cluster_size = bpb.sec_per_clus * SECTOR_SIZE;
    uint8_t* cluster_buf = new uint8_t[cluster_size];

    while (current_cluster >= 2 && current_cluster < FAT_END_OF_CHAIN && remaining > 0) {
        uint32_t to_write = (remaining > cluster_size) ? cluster_size : remaining;
        memset(cluster_buf, 0, cluster_size);
        memcpy(cluster_buf, data_ptr, to_write);
        if (read_write_sectors(g_ahci_port, cluster_to_lba(current_cluster), bpb.sec_per_clus, true, cluster_buf) != 0) { 
            delete[] cluster_buf; 
            return false; 
        }
        data_ptr += to_write;
        remaining -= to_write;
        if (remaining > 0) current_cluster = read_fat_entry(current_cluster);
        else break;
    }
    delete[] cluster_buf;
    return true;
}

uint32_t clusters_needed(uint32_t size) {
    if (bpb.sec_per_clus == 0) return 0;
    uint32_t cluster_size = bpb.sec_per_clus * SECTOR_SIZE;
    return (size + cluster_size - 1) / cluster_size;
}

void fat32_list_files() {
    if (!ahci_base || !current_directory_cluster) {
        wm.print_to_focused("Filesystem not ready.\n");
        return;
    }
    uint32_t cluster_bytes = bpb.sec_per_clus * SECTOR_SIZE;
    uint8_t* buffer = new uint8_t[cluster_bytes];

    wm.print_to_focused("Name                           Size\n");
    char lfn_buf[256] = {0};

    // FAT32 directories are ordinary cluster chains, not single clusters.
    // Once enough entries exist to fill one cluster (trivially easy: a
    // 512-byte cluster only holds 16 entries), the directory spills into
    // a second, third, ... cluster via the FAT chain. The old code only
    // ever read the FIRST cluster, so any files sitting in later clusters
    // — very common right after copying a batch of files in from another
    // OS — silently vanished from `ls`. We now walk the whole chain and
    // only stop when we hit a genuine end-of-directory marker (name[0] ==
    // 0x00), exactly like real FAT32 implementations do.
    uint32_t cluster = current_directory_cluster;
    bool end_of_dir = false;
    while (!end_of_dir && cluster >= 2 && cluster < FAT_END_OF_CHAIN) {
        if (read_write_sectors(g_ahci_port, cluster_to_lba(cluster), bpb.sec_per_clus, false, buffer) != 0) {
            wm.print_to_focused("Read error\n");
            break;
        }

        for (uint32_t i = 0; i < cluster_bytes; i += sizeof(fat_dir_entry_t)) {
            fat_dir_entry_t* entry = (fat_dir_entry_t*)(buffer + i);

            if (entry->name[0] == 0x00) { end_of_dir = true; break; }
            if ((uint8_t)entry->name[0] == DELETED_ENTRY) {
                lfn_buf[0] = '\0';
                continue;
            }
            if (entry->name[0] == '.') continue;

            if (entry->attr == ATTR_LONG_NAME) {
                fat_lfn_entry_t* lfn = (fat_lfn_entry_t*)entry;
                if (lfn->order & 0x40) lfn_buf[0] = '\0';

                char name_part[14] = {0};
                int k = 0;
                auto extract = [&](uint16_t val) {
                    if (k < 13 && val != 0x0000 && val != 0xFFFF) name_part[k++] = (char)val;
                };
                for(int j=0; j<5; j++) extract(lfn->name1[j]);
                for(int j=0; j<6; j++) extract(lfn->name2[j]);
                for(int j=0; j<2; j++) extract(lfn->name3[j]);

                memmove(lfn_buf + k, lfn_buf, strlen(lfn_buf) + 1);
                memcpy(lfn_buf, name_part, k);

            } else if (!(entry->attr & ATTR_VOLUME_ID)) {
                char line[120];
                char fname_83[13];
                const char* name_to_print;

                if (lfn_buf[0] != '\0') {
                    name_to_print = lfn_buf;
                } else {
                    from_83_format(entry->name, fname_83);
                    name_to_print = fname_83;
                }

                // Manually copy and pad the filename to 30 characters
                int name_len = strlen(name_to_print);
                int copy_len = (name_len > 30) ? 30 : name_len;
                memcpy(line, name_to_print, copy_len);
                for (int k = copy_len; k < 30; ++k) {
                    line[k] = ' ';
                }
                line[30] = '\0'; // Terminate after the padded name

                // Use a simple snprintf for just the size
                snprintf(line + 30, 90, " %d\n", entry->file_size);

                wm.print_to_focused(line);
                lfn_buf[0] = '\0'; // Reset for next entry
            }
        }

        if (!end_of_dir) cluster = read_fat_entry(cluster);
    }
    delete[] buffer;
}
int fat32_write_file(const char* filename, const void* data, uint32_t size) {
    // First, safely remove the file if it already exists to handle overwrites correctly.
    fat32_remove_file(filename);

    char target_83[11];
    to_83_format(filename, target_83);
    uint32_t first_cluster = 0;

    if (size > 0) {
        uint32_t num_clusters = clusters_needed(size);
        if (num_clusters == 0) return -1;
        
        first_cluster = allocate_cluster_chain(num_clusters);
        if (first_cluster == 0) return -1; // Out of space
        if (!write_data_to_clusters(first_cluster, data, size)) {
            free_cluster_chain(first_cluster);
            return -1; // Write error
        }
    }

    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];

    // Walk the directory's ENTIRE cluster chain looking for a free slot,
    // instead of only ever looking at the first cluster. A directory is
    // just a cluster chain like any file; a 512-byte cluster only holds
    // 16 entries, so it's trivial to fill the first cluster and spill
    // into a second one — something any real OS handles transparently.
    // Before this fix, once cluster #1 was full this function returned
    // "Directory is full" even with the whole rest of the disk empty,
    // and any files that DID make it into a later cluster (e.g. written
    // by another OS) were invisible to fat32_find_entry/list_files too.
    uint32_t cluster = current_directory_cluster;
    uint32_t last_cluster = cluster;
    while (cluster >= 2 && cluster < FAT_END_OF_CHAIN) {
        last_cluster = cluster;
        for (uint8_t s = 0; s < bpb.sec_per_clus; s++) {
            uint64_t sector_lba = cluster_to_lba(cluster) + s;
            if (read_write_sectors(g_ahci_port, sector_lba, 1, false, dir_buf) != 0) continue;

            for (uint16_t e = 0; e < SECTOR_SIZE / sizeof(fat_dir_entry_t); e++) {
                fat_dir_entry_t* entry = (fat_dir_entry_t*)(dir_buf + e * sizeof(fat_dir_entry_t));
                if (entry->name[0] == 0x00 || (uint8_t)entry->name[0] == DELETED_ENTRY) {
                    // Found a free slot, create the entry.
                    memset(entry, 0, sizeof(fat_dir_entry_t));
                    memcpy(entry->name, target_83, 11);
                    entry->attr = ATTR_ARCHIVE;
                    entry->file_size = size;
                    entry->fst_clus_lo = first_cluster & 0xFFFF;
                    entry->fst_clus_hi = (first_cluster >> 16) & 0xFFFF;

                    if (read_write_sectors(g_ahci_port, sector_lba, 1, true, dir_buf) == 0) {
                        delete[] dir_buf;
                        return 0; // Success
                    } else {
                        delete[] dir_buf;
                        if(first_cluster > 0) free_cluster_chain(first_cluster);
                        return -1; // Directory write error
                    }
                }
            }
        }
        cluster = read_fat_entry(cluster);
    }

    // Every existing directory cluster is completely full (no 0x00 and no
    // deleted-entry slot anywhere in the chain): grow the directory by
    // appending a fresh cluster, exactly like a real FAT32 driver would.
    uint32_t new_dir_cluster = allocate_cluster();
    if (new_dir_cluster == 0) {
        delete[] dir_buf;
        if (first_cluster > 0) free_cluster_chain(first_cluster);
        return -1; // Disk is genuinely full, can't grow the directory
    }

    uint32_t cluster_bytes = bpb.sec_per_clus * SECTOR_SIZE;
    uint8_t* new_clus_buf = new uint8_t[cluster_bytes];
    memset(new_clus_buf, 0, cluster_bytes); // zeroed => first unused entry marks end-of-directory

    fat_dir_entry_t* new_entry = (fat_dir_entry_t*)new_clus_buf;
    memcpy(new_entry->name, target_83, 11);
    new_entry->attr = ATTR_ARCHIVE;
    new_entry->file_size = size;
    new_entry->fst_clus_lo = first_cluster & 0xFFFF;
    new_entry->fst_clus_hi = (first_cluster >> 16) & 0xFFFF;

    bool wrote_ok = (read_write_sectors(g_ahci_port, cluster_to_lba(new_dir_cluster), bpb.sec_per_clus, true, new_clus_buf) == 0);
    delete[] new_clus_buf;
    delete[] dir_buf;

    if (!wrote_ok) {
        free_cluster_chain(new_dir_cluster);
        if (first_cluster > 0) free_cluster_chain(first_cluster);
        return -1;
    }

    // Link the new cluster onto the end of the directory's FAT chain.
    write_fat_entry(last_cluster, new_dir_cluster);
    write_fat_entry(new_dir_cluster, FAT_END_OF_CHAIN);
    return 0;
}

char* fat32_read_file_as_string(const char* filename) {
    char target[11]; to_83_format(filename, target);
    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];
    // Walk the full directory cluster chain (see fat32_list_files() for
    // why this matters) instead of stopping after the first cluster.
    uint32_t cluster = current_directory_cluster;
    while (cluster >= 2 && cluster < FAT_END_OF_CHAIN) {
        for (uint8_t s = 0; s < bpb.sec_per_clus; s++) {
            if (read_write_sectors(g_ahci_port, cluster_to_lba(cluster) + s, 1, false, dir_buf) != 0) { delete[] dir_buf; return nullptr; }
            for (uint16_t e = 0; e < SECTOR_SIZE / sizeof(fat_dir_entry_t); e++) {
                fat_dir_entry_t* entry = (fat_dir_entry_t*)(dir_buf + e * sizeof(fat_dir_entry_t));
                if (entry->name[0] == 0x00) { delete[] dir_buf; return nullptr; }
                if (memcmp(entry->name, target, 11) == 0) {
                    uint32_t size = entry->file_size;
                    if(size == 0) { delete[] dir_buf; char* empty = new char[1]; empty[0] = '\0'; return empty; }
                    char* data = new char[size + 1];
                    if (read_data_from_clusters((entry->fst_clus_hi << 16) | entry->fst_clus_lo, data, size)) {
                        data[size] = '\0';
                        delete[] dir_buf;
                        return data;
                    }
                    delete[] data; delete[] dir_buf; return nullptr;
                }
            }
        }
        cluster = read_fat_entry(cluster);
    }
    delete[] dir_buf; return nullptr;
}

int fat32_find_entry(const char* filename, fat_dir_entry_t* entry_out, uint32_t* sector_out, uint32_t* offset_out) {
    char lfn_buf[256] = {0};
    uint8_t current_checksum = 0;

    // Walk the directory's FULL cluster chain, not just its first cluster.
    // See the comment in fat32_list_files() for why this matters: any
    // entry copied in from another OS that landed past cluster #1 used to
    // be completely invisible to this lookup, which made "cp"/"cat"/open
    // silently fail on files that clearly existed on disk.
    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];
    uint32_t cluster = current_directory_cluster;
    while (cluster >= 2 && cluster < FAT_END_OF_CHAIN) {
        for(uint8_t s=0; s<bpb.sec_per_clus; ++s) {
            uint32_t current_sector = cluster_to_lba(cluster) + s;
            if(read_write_sectors(g_ahci_port, current_sector, 1, false, dir_buf) != 0) {
                delete[] dir_buf;
                return -1;
            }

            for(uint16_t e=0; e < SECTOR_SIZE / sizeof(fat_dir_entry_t); ++e) {
                fat_dir_entry_t* entry = (fat_dir_entry_t*)(dir_buf + e*sizeof(fat_dir_entry_t));
                if(entry->name[0] == 0x00) { delete[] dir_buf; return -1; }
                if((uint8_t)entry->name[0] == DELETED_ENTRY) { lfn_buf[0] = '\0'; continue; }

                if(entry->attr == ATTR_LONG_NAME) {
                    fat_lfn_entry_t* lfn = (fat_lfn_entry_t*)entry;
                    if (lfn->order & 0x40) {
                        lfn_buf[0] = '\0';
                        current_checksum = lfn->checksum;
                    }

                    char name_part[14] = {0};
                    int k = 0;
                    auto extract = [&](uint16_t val) {
                        if (k < 13 && val != 0x0000 && val != 0xFFFF) name_part[k++] = (char)val;
                    };
                    for(int j=0; j<5; j++) extract(lfn->name1[j]);
                    for(int j=0; j<6; j++) extract(lfn->name2[j]);
                    for(int j=0; j<2; j++) extract(lfn->name3[j]);

                    memmove(lfn_buf + k, lfn_buf, strlen(lfn_buf) + 1);
                    memcpy(lfn_buf, name_part, k);

                } else if (!(entry->attr & ATTR_VOLUME_ID)) {
                    bool match = false;
                    if(lfn_buf[0] != '\0' && lfn_checksum((unsigned char*)entry->name) == current_checksum) {
                        if(strcmp(lfn_buf, filename) == 0) match = true;
                    } else {
                        char sfn_name[13];
                        from_83_format(entry->name, sfn_name);
                        if(strcmp(sfn_name, filename) == 0) match = true;
                    }

                    lfn_buf[0] = '\0';

                    if(match) {
                        memcpy(entry_out, entry, sizeof(fat_dir_entry_t));
                        *sector_out = current_sector;
                        *offset_out = e * sizeof(fat_dir_entry_t);
                        delete[] dir_buf;
                        return 0;
                    }
                }
            }
        }
        cluster = read_fat_entry(cluster);
    }
    delete[] dir_buf;
    return -1;
}
// Guest-disk-wrapper helper (see bochs_glue.cpp's bochs_guest_disk_cmd):
// get a file's size without reading its contents. Used both for the
// guest's STAT command and internally by READ, so a too-small buffer
// fails fast (with the real size reported back) instead of paying for
// a full fat32_read_file_as_string() alloc+copy first.
int fat32_stat_file(const char* filename, uint32_t* size_out) {
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    if (fat32_find_entry(filename, &entry, &sector, &offset) != 0) return -1;
    if (size_out) *size_out = entry.file_size;
    return 0;
}

int fat32_list_directory(const char* path, fat_dir_entry_t* buffer, int max_entries) {
    // This implementation ignores 'path' and lists the current directory for simplicity.
    if (!ahci_base || !current_directory_cluster || !buffer) {
        return 0;
    }

    uint32_t cluster_bytes = bpb.sec_per_clus * SECTOR_SIZE;
    uint8_t* dir_sector_buf = new uint8_t[cluster_bytes];

    int count = 0;
    // Walk the full directory cluster chain (see fat32_list_files() for
    // why: entries past the first cluster used to be invisible here too,
    // which is why file explorer / desktop icon lists silently dropped
    // files copied in from another OS).
    uint32_t cluster = current_directory_cluster;
    bool end_of_dir = false;
    while (!end_of_dir && count < max_entries && cluster >= 2 && cluster < FAT_END_OF_CHAIN) {
        if (read_write_sectors(g_ahci_port, cluster_to_lba(cluster), bpb.sec_per_clus, false, dir_sector_buf) != 0) {
            break; // Read error
        }

        for (uint32_t i = 0; i < cluster_bytes; i += sizeof(fat_dir_entry_t)) {
            if (count >= max_entries) break;

            fat_dir_entry_t* entry = (fat_dir_entry_t*)(dir_sector_buf + i);

            if (entry->name[0] == 0x00) { end_of_dir = true; break; } // End of directory
            if ((uint8_t)entry->name[0] == DELETED_ENTRY) continue; // Skip deleted entries
            if (entry->attr == ATTR_LONG_NAME || (entry->attr & ATTR_VOLUME_ID)) continue; // Skip LFN and Volume ID

            // This is a valid file or directory, so copy it to the output buffer
            memcpy(&buffer[count], entry, sizeof(fat_dir_entry_t));
            count++;
        }

        if (!end_of_dir) cluster = read_fat_entry(cluster);
    }

    delete[] dir_sector_buf;
    return count;
}
int fat32_remove_file(const char* filename) {
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    if(fat32_find_entry(filename, &entry, &sector, &offset) != 0) return -1;
    uint32_t start_cluster = (entry.fst_clus_hi << 16) | entry.fst_clus_lo;
    if(start_cluster != 0) free_cluster_chain(start_cluster);
    
    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];
    read_write_sectors(g_ahci_port, sector, 1, false, dir_buf);
    ((fat_dir_entry_t*)(dir_buf + offset))->name[0] = DELETED_ENTRY;
    read_write_sectors(g_ahci_port, sector, 1, true, dir_buf);
    delete[] dir_buf;
    return 0;
}
// ADD THIS NEW FUNCTION after fat32_rename_file
int fat32_copy_file(const char* src_path, const char* dest_path) {
    fat_dir_entry_t entry;
    uint32_t sector, offset;

    // 1. Find the source file and get its info
    if (fat32_find_entry(src_path, &entry, &sector, &offset) != 0) {
        return -1; // Source file not found
    }

    if (entry.file_size == 0) {
        // Handle zero-byte files
        return fat32_write_file(dest_path, nullptr, 0);
    }
    
    // 2. Allocate memory and read the source file's content
    uint8_t* content_buffer = new uint8_t[entry.file_size];
    if (!content_buffer) {
        return -2; // Out of memory
    }

    uint32_t start_cluster = (entry.fst_clus_hi << 16) | entry.fst_clus_lo;
    if (!read_data_from_clusters(start_cluster, content_buffer, entry.file_size)) {
        delete[] content_buffer;
        return -3; // Failed to read source file
    }

    // 3. Write the content to the destination file
    int result = fat32_write_file(dest_path, content_buffer, entry.file_size);
    
    delete[] content_buffer;
    return (result == 0) ? 0 : -4; // Return 0 on success, else write error
}
int fat32_rename_file(const char* old_name, const char* new_name) {
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    fat_dir_entry_t dummy_entry;
    uint32_t dummy_sector, dummy_offset;

    // 1. Check if new_name already exists. If so, fail.
    if (fat32_find_entry(new_name, &dummy_entry, &dummy_sector, &dummy_offset) == 0) {
        return -1; // Destination file already exists
    }

    // 2. Find the old file. If it doesn't exist, fail.
    if (fat32_find_entry(old_name, &entry, &sector, &offset) != 0) {
        return -1; // Source file not found
    }
    
    // 3. Read, modify, and write back the directory sector.
    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];
    if (read_write_sectors(g_ahci_port, sector, 1, false, dir_buf) != 0) {
        delete[] dir_buf;
        return -1;
    }

    fat_dir_entry_t* target_entry = (fat_dir_entry_t*)(dir_buf + offset);
    to_83_format(new_name, target_entry->name);
    
    if (read_write_sectors(g_ahci_port, sector, 1, true, dir_buf) != 0) {
        delete[] dir_buf;
        return -1;
    }

    delete[] dir_buf;
    return 0; // Success
}
void fat32_format() {
    if(!ahci_base) {
        wm.print_to_focused("AHCI disk not found. Cannot format.\n");
        return;
    }
    wm.print_to_focused("WARNING: This is a destructive operation!\nFormatting disk...\n");

    // ─────────────────────────────────────────────────────────────────────
    // Decide partition layout upfront.
    //
    // On a raw disk (g_partition_lba == 0) we will write an MBR and place
    // the FAT32 partition at PART_START_LBA (2048 = 1 MiB, the standard
    // alignment used by fdisk/parted/mkfs.fat).  On a pre-partitioned disk
    // we format in-place at g_partition_lba.
    //
    // IMPORTANT: tot_sec32 in the BPB is the sector count OF THE PARTITION,
    // not the whole disk.  Windows fastfat validates:
    //   cluster_count = (tot_sec32 - rsvd_sec_cnt - num_fats*fat_sz32)
    //                   / sec_per_clus
    // and requires cluster_count >= 65525 for FAT32.  Using the whole-disk
    // sector count here inflates the number and causes chkdsk to report
    // "The volume size is too big" or refuse to mount on small images.
    // ─────────────────────────────────────────────────────────────────────
    const uint32_t PART_START_LBA = 2048;   // 1 MiB boundary (standard)
    const bool raw_disk = (g_partition_lba == 0);

    // Effective partition start that will end up in g_partition_lba after format.
    const uint64_t new_part_lba = raw_disk ? PART_START_LBA : g_partition_lba;

    // Total disk size in sectors (128 MB image).  The partition occupies
    // disk_total_sectors - new_part_lba sectors.
    const uint32_t disk_total_sectors = (128u * 1024u * 1024u) / 512u;
    // Guard: partition must fit within the disk.
    if (new_part_lba >= disk_total_sectors) {
        wm.print_to_focused("Error: partition start beyond disk end.\n");
        return;
    }
    const uint32_t part_total_sectors = disk_total_sectors - (uint32_t)new_part_lba;

    fat32_bpb_t new_bpb;
    memset(&new_bpb, 0, sizeof(fat32_bpb_t));
    new_bpb.jmp[0] = 0xEB; new_bpb.jmp[1] = 0x58; new_bpb.jmp[2] = 0x90;
    memcpy(new_bpb.oem, "MSWIN4.1", 8);
    new_bpb.bytes_per_sec = 512;
    new_bpb.rsvd_sec_cnt  = 32;
    new_bpb.num_fats      = 2;
    new_bpb.root_ent_cnt  = 0;      // must be 0 for FAT32
    new_bpb.tot_sec16     = 0;      // must be 0 for FAT32 (use tot_sec32)
    new_bpb.media         = 0xF8;
    new_bpb.fat_sz16      = 0;      // must be 0 for FAT32 (use fat_sz32)
    new_bpb.sec_per_trk   = 32;
    new_bpb.num_heads     = 64;
    new_bpb.hidd_sec      = (uint32_t)new_part_lba;  // sectors before this partition
    new_bpb.tot_sec32     = part_total_sectors;        // partition size, NOT disk size

    // ── sec_per_clus: smallest value that yields >= 65525 clusters ────────
    {
        uint8_t spc_candidates[] = { 1, 2, 4, 8, 16, 32, 64, 128 };
        uint8_t chosen = 128; // safe fallback
        for (uint32_t k = 0; k < sizeof(spc_candidates); k++) {
            uint8_t spc = spc_candidates[k];
            uint32_t tmp1 = part_total_sectors - new_bpb.rsvd_sec_cnt;
            uint32_t tmp2 = (256u * spc + new_bpb.num_fats) / 2u;
            uint32_t fat_sz = (tmp1 + tmp2 - 1u) / tmp2;
            uint32_t data_sec = part_total_sectors
                                - new_bpb.rsvd_sec_cnt
                                - new_bpb.num_fats * fat_sz;
            uint32_t clusters = data_sec / spc;
            if (clusters >= 65525u) { chosen = spc; break; }
        }
        new_bpb.sec_per_clus = chosen;
    }

    // ── fat_sz32 from Microsoft FAT spec section 3.5 ─────────────────────
    {
        uint32_t tmp1 = part_total_sectors - new_bpb.rsvd_sec_cnt;
        uint32_t tmp2 = (256u * new_bpb.sec_per_clus + new_bpb.num_fats) / 2u;
        new_bpb.fat_sz32 = (tmp1 + tmp2 - 1u) / tmp2;
    }

    new_bpb.root_clus   = 2;
    new_bpb.fs_info     = 1;        // FSInfo at partition + 1
    new_bpb.bk_boot_sec = 6;        // backup boot sector at partition + 6
    new_bpb.ext_flags   = 0;        // mirror FATs
    new_bpb.fs_ver      = 0x0000;   // FAT32 version 0.0 — required by spec
    new_bpb.drv_num     = 0x80;
    new_bpb.res1        = 0;
    new_bpb.boot_sig    = 0x29;
    new_bpb.vol_id      = 0x12345678;
    memcpy(new_bpb.vol_lab,      "MYOS VOL   ", 11);
    memcpy(new_bpb.fil_sys_type, "FAT32   ",    8);

    // ── Commit globals NOW, before any sector writes that depend on them ──
    // All write helpers (write_fat_entry, cluster_to_lba, …) use the
    // module-level fat_start_sector / data_start_sector globals, so they
    // must be correct before we call them — not after.
    memcpy(&bpb, &new_bpb, sizeof(fat32_bpb_t));
    g_partition_lba   = new_part_lba;
    fat_start_sector  = (uint32_t)(new_part_lba + bpb.rsvd_sec_cnt);
    data_start_sector = fat_start_sector + (bpb.num_fats * bpb.fat_sz32);

    // ── Write MBR (raw disk only) ─────────────────────────────────────────
    if (raw_disk) {
        wm.print_to_focused("Writing MBR and partition table...\n");
        char* mbr = new char[SECTOR_SIZE];
        memset(mbr, 0, SECTOR_SIZE);

        // Minimal x86 bootstrap stub (prints "No bootable OS", halts).
        static const uint8_t boot_stub[] = {
            0xFA,                         // CLI
            0x31, 0xC0,                   // XOR AX, AX
            0x8E, 0xD0,                   // MOV SS, AX
            0xBC, 0x00, 0x7C,             // MOV SP, 0x7C00
            0xFB,                         // STI
            0x0E,                         // PUSH CS
            0x1F,                         // POP DS
            0xBE, 0x1E, 0x7C,             // MOV SI, msg_offset
            0xAC,                         // LODSB
            0x08, 0xC0,                   // OR AL, AL
            0x74, 0x09,                   // JZ halt
            0xB4, 0x0E,                   // MOV AH, 0x0E
            0xBB, 0x07, 0x00,             // MOV BX, 7
            0xCD, 0x10,                   // INT 0x10
            0xEB, 0xF2,                   // JMP loop
            0xF4,                         // HLT
            0xEB, 0xFD,                   // JMP halt
            'N','o',' ','b','o','o','t','a','b','l','e',' ','O','S','\r','\n', 0x00
        };
        memcpy(mbr, boot_stub, sizeof(boot_stub));

        // Partition table entry 0: type 0x0C (FAT32 LBA), bootable.
        // CHS values set to 0xFE/0xFF/0xFF (LBA-mode placeholder, per
        // the convention used by Windows Disk Management and fdisk).
        uint8_t* pt = (uint8_t*)mbr + 446;
        pt[0] = 0x80;                                // bootable
        pt[1] = 0xFE; pt[2] = 0xFF; pt[3] = 0xFF;  // CHS start placeholder
        pt[4] = 0x0C;                                // type: FAT32 LBA
        pt[5] = 0xFE; pt[6] = 0xFF; pt[7] = 0xFF;  // CHS end placeholder
        *(uint32_t*)(pt +  8) = PART_START_LBA;
        *(uint32_t*)(pt + 12) = part_total_sectors;
        // Entries 1–3: zeroed (unused).

        mbr[510] = (char)0x55;
        mbr[511] = (char)0xAA;

        bool was = g_fs_encryption_enabled;
        g_fs_encryption_enabled = false;
        if (read_write_sectors(g_ahci_port, 0, 1, true, mbr) != 0)
            wm.print_to_focused("Warning: MBR write failed.\n");
        else
            wm.print_to_focused("MBR + partition table written.\n");
        g_fs_encryption_enabled = was;
        delete[] mbr;
    }

    // ── Write VBR (Volume Boot Record = BPB sector) at new_part_lba ──────
    wm.print_to_focused("Writing volume boot record...\n");
    char* boot_sector_buffer = new char[SECTOR_SIZE];
    memset(boot_sector_buffer, 0, SECTOR_SIZE);
    memcpy(boot_sector_buffer, &new_bpb, sizeof(fat32_bpb_t));
    boot_sector_buffer[510] = (char)0x55;
    boot_sector_buffer[511] = (char)0xAA;

    bool boot_sec_was_enc = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;   // BPB/FSInfo must be plaintext

    if (read_write_sectors(g_ahci_port, new_part_lba, 1, true, boot_sector_buffer) != 0) {
        wm.print_to_focused("Error: Failed to write volume boot record.\n");
        delete[] boot_sector_buffer;
        g_fs_encryption_enabled = boot_sec_was_enc;
        return;
    }
    // Backup VBR at partition + bk_boot_sec (=6).
    wm.print_to_focused("Writing backup boot sector...\n");
    if (read_write_sectors(g_ahci_port, new_part_lba + new_bpb.bk_boot_sec, 1,
                           true, boot_sector_buffer) != 0)
        wm.print_to_focused("Warning: backup boot sector write failed.\n");

    // ── Write FSInfo sector at partition + fs_info (=1) ───────────────────
    // Signatures per FAT32 spec Table 9:
    //   offset   0  LeadSig  = 0x41615252  ("RRaA")
    //   offset 484  StrucSig = 0x61417272  ("rrAa")
    //   offset 488  FreeCount= 0xFFFFFFFF  (unknown — recompute on first mount)
    //   offset 492  NextFree = 0xFFFFFFFF  (unknown — search from cluster 2)
    //   offset 508  TrailSig = 0xAA550000
    wm.print_to_focused("Writing FSInfo sector...\n");
    memset(boot_sector_buffer, 0, SECTOR_SIZE);
    *(uint32_t*)(boot_sector_buffer +   0) = 0x41615252u;
    *(uint32_t*)(boot_sector_buffer + 484) = 0x61417272u;
    *(uint32_t*)(boot_sector_buffer + 488) = 0xFFFFFFFFu;
    *(uint32_t*)(boot_sector_buffer + 492) = 0xFFFFFFFFu;
    *(uint32_t*)(boot_sector_buffer + 508) = 0xAA550000u;
    if (read_write_sectors(g_ahci_port, new_part_lba + new_bpb.fs_info, 1,
                           true, boot_sector_buffer) != 0)
        wm.print_to_focused("Warning: FSInfo sector write failed.\n");
    // Backup FSInfo at bk_boot_sec + 1 (recommended by spec, not required).
    read_write_sectors(g_ahci_port, new_part_lba + new_bpb.bk_boot_sec + 1, 1,
                       true, boot_sector_buffer);

    delete[] boot_sector_buffer;
    g_fs_encryption_enabled = boot_sec_was_enc;

    // ── Clear FAT1 + FAT2 ─────────────────────────────────────────────────
    // fat_start_sector already reflects the correct absolute LBA.
    uint8_t* zero_sector = new uint8_t[SECTOR_SIZE];
    memset(zero_sector, 0, SECTOR_SIZE);
    wm.print_to_focused("Clearing FATs...\n");
    for (uint32_t i = 0; i < bpb.fat_sz32; ++i) {
        read_write_sectors(g_ahci_port, fat_start_sector + i, 1, true, zero_sector);                    // FAT1
        read_write_sectors(g_ahci_port, fat_start_sector + bpb.fat_sz32 + i, 1, true, zero_sector);    // FAT2
    }

    // ── Clear root directory cluster ───────────────────────────────────────
    wm.print_to_focused("Clearing root directory...\n");
    for (uint8_t i = 0; i < bpb.sec_per_clus; ++i) {
        read_write_sectors(g_ahci_port, cluster_to_lba(bpb.root_clus) + i, 1, true, zero_sector);
    }
    delete[] zero_sector;

    // ── Write initial FAT entries ──────────────────────────────────────────
    // Cluster 0: media-type byte (0x0FFFFF_F8 for fixed disk, mirroring BPB_Media).
    // Cluster 1: end-of-chain / dirty-flag word (0x0FFFFFFF = clean).
    // Cluster 2: root directory — single cluster, end of chain.
    wm.print_to_focused("Writing initial FAT entries...\n");
    write_fat_entry(0, 0x0FFFFFF8); // Media descriptor
    write_fat_entry(1, 0x0FFFFFFF); // Clean/EOC
    write_fat_entry(bpb.root_clus, 0x0FFFFFFF); // Root directory EOC

    // ─────────────────────────────────────────────────────────────────────
    // Volume label directory entry in the root cluster.
    //
    // The FAT32 spec (section 6) requires that the first entry in the root
    // directory is a volume-label entry (ATTR_VOLUME_ID = 0x08) whose
    // DIR_Name field matches BPB_VolLab. Without it Windows Explorer shows
    // "Local Disk" instead of the volume name, and chkdsk reports a missing
    // volume label as a warning.
    //
    // The entry is written AFTER the initial FAT entries so that
    // cluster_to_lba(bpb.root_clus) is already valid and fat_start_sector
    // / data_start_sector have been updated for the MBR-partition case.
    // ─────────────────────────────────────────────────────────────────────
    {
        uint8_t* root_sector = new uint8_t[SECTOR_SIZE];
        memset(root_sector, 0, SECTOR_SIZE);
        fat_dir_entry_t* vol_entry = (fat_dir_entry_t*)root_sector;
        memcpy(vol_entry->name, new_bpb.vol_lab, 11); // "MYOS VOL   "
        vol_entry->attr = ATTR_VOLUME_ID;
        // crt_time / crt_date — use a fixed timestamp (2024-01-01 00:00:00).
        // FAT date: bits 15-9 = year-1980, bits 8-5 = month, bits 4-0 = day.
        // FAT time: bits 15-11 = hour, bits 10-5 = minute, bits 4-0 = sec/2.
        vol_entry->crt_date = (uint16_t)((44 << 9) | (1 << 5) | 1); // 2024-01-01
        vol_entry->wrt_date = vol_entry->crt_date;
        vol_entry->lst_acc_date = vol_entry->crt_date;
        vol_entry->fst_clus_hi = 0;
        vol_entry->fst_clus_lo = 0;
        vol_entry->file_size   = 0;
        // Write to the first sector of the root cluster (already zeroed
        // above, but we only wrote zeros — the volume entry goes here now).
        bool vl_ok = (read_write_sectors(
            g_ahci_port, cluster_to_lba(bpb.root_clus), 1, true, root_sector) == 0);
        if (!vl_ok) wm.print_to_focused("Warning: volume label dir entry write failed.\n");
        delete[] root_sector;
        wm.print_to_focused("Volume label directory entry written.\n");
    }

    wm.print_to_focused("Format complete. Re-initializing filesystem...\n");
    if (fat32_init()) {
        wm.print_to_focused("FAT32 FS re-initialized successfully.\n");
    } else {
        wm.print_to_focused("FAT32 FS re-initialization failed.\n");
        // Diagnostic: read the BPB sector back as plaintext and report what
        // is actually on disk. g_partition_lba is the partition's first
        // sector (sector 0 holds the MBR on a raw disk, not the BPB).
        char* vb = new char[SECTOR_SIZE];
        if (vb) {
            bool was = g_fs_encryption_enabled;
            g_fs_encryption_enabled = false;
            int rr = read_write_sectors(g_ahci_port, g_partition_lba, 1, false, vb);
            g_fs_encryption_enabled = was;
            if (rr != 0) {
                wm.print_to_focused("  diag: boot-sector read-back FAILED.\n");
            } else {
                // fil_sys_type sits at BPB offset 82.
                char fst[9];
                for (int k = 0; k < 8; ++k) fst[k] = vb[82 + k];
                fst[8] = '\0';
                uint8_t s0 = (uint8_t)vb[510], s1 = (uint8_t)vb[511];
                char msg[80];
                snprintf(msg, sizeof(msg),
                         "  diag: fs_type='%s' sig=%02X%02X\n",
                         fst, s0, s1);
                wm.print_to_focused(msg);
            }
            delete[] vb;
        }
    }
}
class FileExplorerWindow : public Window {
private:
    char current_path[256];
    fat_dir_entry_t file_list[128];
    int num_files;
    int scroll_offset;
    int selected_index;

    // --- List / scrollbar geometry constants ---
    // ROW_H must be >= the small icon size (14px) plus a little padding so
    // rows never overlap/clip into each other.
    static constexpr int TITLEBAR_H   = 25;
    static constexpr int LIST_TOP_PAD = 5;   // gap below titlebar before first row
    static constexpr int ROW_H        = 18;
    static constexpr int SCROLLBAR_W  = 16;  // width of the scroll sidebar
    static constexpr int ARROW_H      = 16;  // height of each up/down arrow button

    int list_area_x() const { return x; }
    int list_area_y() const { return y + TITLEBAR_H; }
    int list_area_w() const { return w - SCROLLBAR_W; }
    int list_area_h() const { return h - TITLEBAR_H; }

    int max_visible_items() const {
        int n = (list_area_h() - LIST_TOP_PAD) / ROW_H;
        return n < 1 ? 1 : n;
    }

    int max_scroll_offset() const {
        int m = num_files - max_visible_items();
        return m < 0 ? 0 : m;
    }

    void clamp_scroll() {
        int max_off = max_scroll_offset();
        if (scroll_offset > max_off) scroll_offset = max_off;
        if (scroll_offset < 0) scroll_offset = 0;
    }

    int scrollbar_x() const { return x + w - SCROLLBAR_W; }
    int scrollbar_top() const { return y + TITLEBAR_H; }
    int scrollbar_track_top() const { return scrollbar_top() + ARROW_H; }
    int scrollbar_track_h() const { return list_area_h() - 2 * ARROW_H; }

    // Peeks at a file's first 4 bytes and checks them against the ELF
    // magic number (0x7F 'E' 'L' 'F'), the same check validate_elf_header()
    // does on the full header. We deliberately don't depend on the
    // Elf32_Ehdr type here (it's defined much later in this translation
    // unit, after FileExplorerWindow) — a raw byte comparison is all
    // "is this actually an ELF" requires.
    bool is_elf_file(int idx) {
        if (idx < 0 || idx >= num_files) return false;
        if (file_list[idx].attr & FAT_ATTR_DIRECTORY) return false;
        if (file_list[idx].file_size < 4) return false;

        char filename[13];
        fat32_get_fne_from_entry(&file_list[idx], filename);
        char* data = fat32_read_file_as_string(filename);
        if (!data) return false;

        bool is_elf = (unsigned char)data[0] == 0x7F &&
                       data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
        delete[] data;
        return is_elf;
    }

    // Double-click / right-click "Run" behavior: inspect the actual file
    // contents (not just its extension) and either launch it through the
    // Bochs CPU emulator (ELF binaries) or open it in the text editor
    // (anything else). "bochs <file>" is used rather than "run <file>" —
    // "run" is not a recognized shell command in handle_command(), so
    // building a "run %s" command string (as this code used to) silently
    // failed; "bochs" is the actual working ELF-execution entry point.
    void open_or_run(int idx) {
        if (idx < 0 || idx >= num_files) return;
        if (file_list[idx].attr & FAT_ATTR_DIRECTORY) return; // directory navigation not implemented yet

        char filename[13];
        fat32_get_fne_from_entry(&file_list[idx], filename);

        char command_buffer[128];
        if (is_elf_file(idx)) {
            snprintf(command_buffer, sizeof(command_buffer), "bochs %s", filename);
        } else {
            snprintf(command_buffer, sizeof(command_buffer), "edit \"%s\"", filename);
        }
        launch_terminal_with_command(command_buffer);
    }

    // Returns true and consumes the click if it landed on the scrollbar.
    bool handle_scrollbar_click(int mx, int my) {
        if (mx < scrollbar_x() || mx >= scrollbar_x() + SCROLLBAR_W) return false;
        if (my < scrollbar_top() || my >= scrollbar_top() + list_area_h()) return false;

        int sb_top = scrollbar_top();
        int track_top = scrollbar_track_top();
        int track_h = scrollbar_track_h();

        if (my < sb_top + ARROW_H) {
            // Up arrow
            scroll_offset--;
        } else if (my >= sb_top + list_area_h() - ARROW_H) {
            // Down arrow
            scroll_offset++;
        } else if (track_h > 0) {
            // Track click: page up/down relative to the thumb position
            int visible = max_visible_items();
            int max_off = max_scroll_offset();
            int thumb_h = max_off > 0 ? (track_h * visible) / num_files : track_h;
            if (thumb_h < 8) thumb_h = 8;
            if (thumb_h > track_h) thumb_h = track_h;
            int thumb_y = track_top;
            if (max_off > 0) {
                thumb_y = track_top + ((track_h - thumb_h) * scroll_offset) / max_off;
            }
            if (my < thumb_y) {
                scroll_offset -= visible; // page up
            } else if (my >= thumb_y + thumb_h) {
                scroll_offset += visible; // page down
            }
        }
        clamp_scroll();
        return true;
    }

    void draw_scrollbar() {
        using namespace ColorPalette;
        int sb_x = scrollbar_x();
        int sb_top = scrollbar_top();
        int sb_h = list_area_h();

        // Track background
        draw_rect_filled(sb_x, sb_top, SCROLLBAR_W, sb_h, BUTTON_FACE);
        draw_rect_filled(sb_x, sb_top, 1, sb_h, BUTTON_SHADOW);

        // Up arrow button
        draw_rect_filled(sb_x + 1, sb_top + 1, SCROLLBAR_W - 2, ARROW_H - 2, BUTTON_FACE);
        draw_rect_filled(sb_x + 1, sb_top + 1, SCROLLBAR_W - 2, 1, BUTTON_HIGHLIGHT);
        draw_rect_filled(sb_x + 1, sb_top + ARROW_H - 2, SCROLLBAR_W - 2, 1, BUTTON_SHADOW);
        draw_char('^', sb_x + 4, sb_top + 4, TEXT_BLACK);

        // Down arrow button
        int down_y = sb_top + sb_h - ARROW_H;
        draw_rect_filled(sb_x + 1, down_y + 1, SCROLLBAR_W - 2, ARROW_H - 2, BUTTON_FACE);
        draw_rect_filled(sb_x + 1, down_y + 1, SCROLLBAR_W - 2, 1, BUTTON_HIGHLIGHT);
        draw_rect_filled(sb_x + 1, down_y + ARROW_H - 2, SCROLLBAR_W - 2, 1, BUTTON_SHADOW);
        draw_char('v', sb_x + 4, down_y + 4, TEXT_BLACK);

        // Thumb
        int track_top = scrollbar_track_top();
        int track_h = scrollbar_track_h();
        if (track_h > 0) {
            int visible = max_visible_items();
            int max_off = max_scroll_offset();
            int thumb_h = max_off > 0 ? (track_h * visible) / (num_files > 0 ? num_files : 1) : track_h;
            if (thumb_h < 8) thumb_h = 8;
            if (thumb_h > track_h) thumb_h = track_h;
            int thumb_y = track_top;
            if (max_off > 0) {
                thumb_y = track_top + ((track_h - thumb_h) * scroll_offset) / max_off;
            }
            draw_rect_filled(sb_x + 2, thumb_y, SCROLLBAR_W - 4, thumb_h, BUTTON_SHADOW);
            draw_rect_filled(sb_x + 2, thumb_y, SCROLLBAR_W - 4, 1, BUTTON_HIGHLIGHT);
        }
    }

public:
    FileExplorerWindow(int x, int y, const char* path) 
        : Window(x, y, 400, 300, "File Explorer"), num_files(0), scroll_offset(0), selected_index(-1) {
        strncpy(current_path, path, 255);
        current_path[255] = '\0';
        refresh_contents();
    }

    void refresh_contents() override {
        num_files = fat32_list_directory(current_path, file_list, 128);
        if (selected_index >= num_files) selected_index = -1;
        clamp_scroll();
    }

    void draw() override {
        if (is_closed) return;
        using namespace ColorPalette;
        
        uint32_t titlebar_color = has_focus ? TITLEBAR_ACTIVE : TITLEBAR_INACTIVE;
        draw_rect_filled(x, y, w, 25, titlebar_color);
        draw_string(title, x + 5, y + 8, TEXT_WHITE);
        draw_string(current_path, x+100, y+8, TEXT_WHITE);

        draw_rect_filled(x + w - 22, y + 4, 18, 18, BUTTON_CLOSE);
        draw_string("X", x + w - 17, y + 8, TEXT_WHITE);
        
        // Main content area
        draw_rect_filled(x, y + 25, w, h - 25, FILE_EXPLORER_BG);
        
        // Draw borders
        for (int i = 0; i < w; i++) put_pixel_back(x + i, y, WINDOW_BORDER);
        for (int i = 0; i < w; i++) put_pixel_back(x + i, y + h - 1, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x, y + i, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x + w - 1, y + i, WINDOW_BORDER);

        clamp_scroll();

        // Draw file list — rows are ROW_H tall and icons are the small
        // (14x14) variant, so each row's icon fits entirely within its own
        // row and never bleeds into neighboring rows.
        int visible = max_visible_items();
        int la_x = list_area_x();
        int la_y = list_area_y();
        int la_w = list_area_w();

        for (int i = 0; i < visible; ++i) {
            int file_idx = scroll_offset + i;
            if (file_idx >= num_files) break;

            int item_y = la_y + LIST_TOP_PAD + i * ROW_H;
            char filename[13];
            fat32_get_fne_from_entry(&file_list[file_idx], filename);

            if (file_idx == selected_index) {
                draw_rect_filled(la_x + 2, item_y, la_w - 4, ROW_H - 2, TITLEBAR_ACTIVE);
            }

            if (file_list[file_idx].attr & FAT_ATTR_DIRECTORY) {
                draw_icon_folder_small(la_x + 4, item_y + 2);
            } else {
                bool is_shortcut = strstr(filename, ".LNK") != nullptr;
                draw_icon_file_small(la_x + 4, item_y + 2, is_shortcut);
            }

            uint32_t name_color = (file_idx == selected_index) ? TEXT_WHITE : TEXT_BLACK;
            draw_string(filename, la_x + 24, item_y + 5, name_color);
        }

        // Scroll sidebar — always drawn so the list column width is
        // consistent, and it visually communicates whether there's more
        // content (short/tall thumb) even when nothing is scrollable yet.
        draw_scrollbar();
    }

    void on_key_press(char c) override {
        // Handle keyboard navigation later
    }

    void on_mouse_right_click(int mx, int my) override {
        // Right-clicks on the scrollbar shouldn't open a file context menu.
        if (mx >= scrollbar_x() && mx < scrollbar_x() + SCROLLBAR_W) return;

        int content_y = my - (list_area_y() + LIST_TOP_PAD);
        if (content_y < 0) return;
        int clicked_idx = scroll_offset + (content_y / ROW_H);

        if (clicked_idx < num_files) {
            selected_index = clicked_idx;
            char filename[13];
            fat32_get_fne_from_entry(&file_list[clicked_idx], filename);

            // Tell the window manager to show the context menu for this
            // file. "Run" is offered whenever the file's contents are
            // actually an ELF binary, not just when its name ends in
            // .obj/.OBJ.
            wm.show_file_context_menu(mx, my, filename, is_elf_file(clicked_idx));
        }
    }

    void on_mouse_click(int mx, int my) override {
        // Scrollbar clicks (arrows / track) are handled here and don't
        // affect file selection.
        if (handle_scrollbar_click(mx, my)) return;

        int content_y = my - (list_area_y() + LIST_TOP_PAD);
        if (content_y < 0) return;
        int clicked_idx = scroll_offset + (content_y / ROW_H);
        
        if(clicked_idx < num_files) {
            selected_index = clicked_idx;
            // Basic double-click simulation
            static int last_click_idx = -1;
            static uint32_t last_click_tick = 0;
            if(clicked_idx == last_click_idx && (g_timer_ticks - last_click_tick) < 20) {
                // Double click! Open in the editor, or run it in the
                // emulator, depending on whether it's actually an ELF.
                open_or_run(clicked_idx);
            }
            last_click_idx = clicked_idx;
            last_click_tick = g_timer_ticks;
        }
    }

    void update() override {}
};
