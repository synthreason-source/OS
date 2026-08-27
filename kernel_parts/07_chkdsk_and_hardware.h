#pragma once
// 07_chkdsk_and_hardware.h
// chkdsk filesystem-check implementation and hardware/device
// enumeration helpers.
// Extracted from kernel.cpp (original lines 4348-5408) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.

// ==================== CHKDSK IMPLEMENTATION ====================

struct ChkdskStats {
    uint32_t total_clusters;
    uint32_t used_clusters;
    uint32_t free_clusters;
    uint32_t bad_clusters;
    uint32_t lost_clusters;
    uint32_t directories_checked;
    uint32_t files_checked;
    uint32_t errors_found;
    uint32_t errors_fixed;
};

static uint32_t* cluster_bitmap = nullptr;
static uint32_t cluster_bitmap_size = 0;

void init_cluster_bitmap() {
    uint32_t total_clusters = fat32_max_clusters();
    cluster_bitmap_size = (total_clusters + 31) / 32;
    
    if (cluster_bitmap) delete[] cluster_bitmap;
    cluster_bitmap = new uint32_t[cluster_bitmap_size];
    memset(cluster_bitmap, 0, cluster_bitmap_size * sizeof(uint32_t));
}

void mark_cluster_used(uint32_t cluster) {
    if (cluster < 2) return;
    uint32_t index = cluster / 32;
    uint32_t bit = cluster % 32;
    if (index < cluster_bitmap_size) {
        cluster_bitmap[index] |= (1 << bit);
    }
}

bool is_cluster_marked(uint32_t cluster) {
    if (cluster < 2) return false;
    uint32_t index = cluster / 32;
    uint32_t bit = cluster % 32;
    if (index < cluster_bitmap_size) {
        return (cluster_bitmap[index] & (1 << bit)) != 0;
    }
    return false;
}

bool is_valid_cluster(uint32_t cluster) {
    if (cluster < 2) return false;
    uint32_t max_clusters = fat32_max_clusters();
    return cluster < max_clusters;
}

bool verify_fat_chain(uint32_t start_cluster, uint32_t* chain_length, ChkdskStats& stats) {
    uint32_t current = start_cluster;
    uint32_t count = 0;
    const uint32_t MAX_CHAIN_LENGTH = 1000000;
    
    while (current >= 2 && current < FAT_END_OF_CHAIN && count < MAX_CHAIN_LENGTH) {
        if (!is_valid_cluster(current)) {
            wm.print_to_focused("  ERROR: Invalid cluster in chain!");
            stats.errors_found++;
            return false;
        }
        
        if (is_cluster_marked(current)) {
            wm.print_to_focused("  ERROR: Cross-linked cluster detected!");
            stats.errors_found++;
            return false;
        }
        
        mark_cluster_used(current);
        count++;
        current = read_fat_entry(current);
    }
    
    if (count >= MAX_CHAIN_LENGTH) {
        wm.print_to_focused("  ERROR: Circular FAT chain detected!");
        stats.errors_found++;
        return false;
    }
    
    *chain_length = count;
    return true;
}

bool check_directory_entry(fat_dir_entry_t* entry, ChkdskStats& stats, bool fix) {
    bool has_error = false;
    
    uint32_t start_cluster = (entry->fst_clus_hi << 16) | entry->fst_clus_lo;
    
    if (start_cluster != 0) {
        uint32_t chain_length = 0;
        if (!verify_fat_chain(start_cluster, &chain_length, stats)) {
            has_error = true;
            if (fix) {
                wm.print_to_focused("  FIXING: Truncating bad cluster chain...");
                entry->fst_clus_lo = 0;
                entry->fst_clus_hi = 0;
                entry->file_size = 0;
                stats.errors_fixed++;
            }
        } else {
            uint32_t cluster_size = bpb.sec_per_clus * SECTOR_SIZE;
            uint32_t expected_max_size = chain_length * cluster_size;
            
            if (entry->file_size > expected_max_size) {
                wm.print_to_focused("  ERROR: File size exceeds allocated clusters!");
                stats.errors_found++;
                has_error = true;
                
                if (fix) {
                    entry->file_size = expected_max_size;
                    wm.print_to_focused("  FIXED: Corrected file size");
                    stats.errors_fixed++;
                }
            }
        }
    } else if (entry->file_size != 0) {
        wm.print_to_focused("  ERROR: File has size but no cluster allocation!");
        stats.errors_found++;
        has_error = true;
        
        if (fix) {
            entry->file_size = 0;
            wm.print_to_focused("  FIXED: Reset file size to 0");
            stats.errors_fixed++;
        }
    }
    
    return !has_error;
}

bool scan_directory(uint32_t start_cluster, ChkdskStats& stats, bool fix, int depth = 0) {
    if (depth > 20) {
        wm.print_to_focused("ERROR: Directory nesting too deep!");
        return false;
    }
    
    stats.directories_checked++;

    uint32_t cluster_bytes = bpb.sec_per_clus * SECTOR_SIZE;
    uint8_t* buffer = new uint8_t[cluster_bytes];

    // Create a working copy for modifications
    uint8_t* working_buffer = nullptr;
    if (fix) {
        working_buffer = new uint8_t[cluster_bytes];
    }

    bool ok = true;

    // A directory is an ordinary cluster chain, exactly like a file. The
    // previous version of this function only ever looked at the FIRST
    // cluster of the chain, so any entries that spilled into a second or
    // later cluster (trivial to hit: a 512-byte cluster holds only 16
    // entries) were never scanned, never marked "in use" in the cluster
    // bitmap, and their files never appeared as checked by chkdsk. This
    // is the same root cause behind files copied in from another OS
    // going missing from `ls` — we now walk the whole chain, stopping
    // only at a genuine end-of-directory marker (name[0] == 0x00).
    uint32_t cluster = start_cluster;
    bool end_of_dir = false;
    while (!end_of_dir && cluster >= 2 && cluster < FAT_END_OF_CHAIN) {
        mark_cluster_used(cluster);

        if (read_write_sectors(g_ahci_port, cluster_to_lba(cluster), bpb.sec_per_clus, false, buffer) != 0) {
            wm.print_to_focused("ERROR: Cannot read directory cluster");
            ok = false;
            break;
        }

        if (fix) memcpy(working_buffer, buffer, cluster_bytes);
        bool modified = false;

        for (uint32_t i = 0; i < cluster_bytes; i += sizeof(fat_dir_entry_t)) {
            // Use working buffer if fixing, otherwise use read-only buffer
            fat_dir_entry_t* entry = (fat_dir_entry_t*)((fix ? working_buffer : buffer) + i);

            if (entry->name[0] == 0x00) { end_of_dir = true; break; }
            if ((uint8_t)entry->name[0] == DELETED_ENTRY) continue;
            if (entry->name[0] == '.') continue;

            if (entry->attr == ATTR_LONG_NAME) continue;
            if (entry->attr & ATTR_VOLUME_ID) continue;

            stats.files_checked++;

            char fname[13];
            from_83_format(entry->name, fname);

            char msg[100];
            snprintf(msg, 100, "Checking: %s", fname);
            wm.print_to_focused(msg);

            // Only mark as modified if we're in fix mode and something changed
            if (!check_directory_entry(entry, stats, fix)) {
                if (fix) {
                    modified = true;
                }
            }

            if (entry->attr & 0x10) {
                uint32_t subcluster = (entry->fst_clus_hi << 16) | entry->fst_clus_lo;
                if (subcluster >= 2 && subcluster < FAT_END_OF_CHAIN) {
                    if (!is_cluster_marked(subcluster)) {
                        scan_directory(subcluster, stats, fix, depth + 1);
                    }
                }
            }
        }

        // ONLY write back if in fix mode AND something was modified
        if (fix && modified) {
            read_write_sectors(g_ahci_port, cluster_to_lba(cluster), bpb.sec_per_clus, true, working_buffer);
        }

        if (!end_of_dir) cluster = read_fat_entry(cluster);
    }

    delete[] buffer;
    if (working_buffer) {
        delete[] working_buffer;
    }

    return ok;
}


void find_lost_clusters(ChkdskStats& stats, bool fix) {
    wm.print_to_focused("\nScanning for lost clusters...");
    
    uint32_t max_clusters = fat32_max_clusters();
    
    for (uint32_t cluster = 2; cluster < max_clusters; cluster++) {
        uint32_t fat_entry = read_fat_entry(cluster);
        
        if (fat_entry != FAT_FREE_CLUSTER && !is_cluster_marked(cluster)) {
            stats.lost_clusters++;
            
            char msg[80];
            snprintf(msg, 80, "  Lost cluster chain starting at %d", cluster);
            wm.print_to_focused(msg);
            
            if (fix) {
                uint32_t current = cluster;
                while (current >= 2 && current < FAT_END_OF_CHAIN) {
                    uint32_t next = read_fat_entry(current);
                    write_fat_entry(current, FAT_FREE_CLUSTER);
                    current = next;
                    stats.errors_fixed++;
                }
                wm.print_to_focused("  FIXED: Freed lost cluster chain");
            }
        }
    }
}

bool check_fat_consistency(ChkdskStats& stats, bool fix) {
    wm.print_to_focused("Checking FAT table consistency...");
    
    if (bpb.num_fats < 2) {
        wm.print_to_focused("WARNING: Only one FAT copy present!");
        return true;
    }
    
    uint32_t fat_size = bpb.fat_sz32 * SECTOR_SIZE;
    uint8_t* fat1 = new uint8_t[fat_size];
    uint8_t* fat2 = new uint8_t[fat_size];
    
    read_write_sectors(g_ahci_port, fat_start_sector, bpb.fat_sz32, false, fat1);
    read_write_sectors(g_ahci_port, fat_start_sector + bpb.fat_sz32, bpb.fat_sz32, false, fat2);
    
    bool mismatch = false;
    for (uint32_t i = 0; i < fat_size; i++) {
        if (fat1[i] != fat2[i]) {
            mismatch = true;
            break;
        }
    }
    
    if (mismatch) {
        wm.print_to_focused("ERROR: FAT1 and FAT2 do not match!");
        stats.errors_found++;
        
        if (fix) {
            wm.print_to_focused("FIXING: Copying FAT1 to FAT2...");
            read_write_sectors(g_ahci_port, fat_start_sector + bpb.fat_sz32, bpb.fat_sz32, true, fat1);
            stats.errors_fixed++;
            wm.print_to_focused("FIXED: FAT tables synchronized");
        }
    } else {
        wm.print_to_focused("OK: FAT tables are consistent");
    }
    
    delete[] fat1;
    delete[] fat2;
    return !mismatch;
}
void chkdsk(bool fix = false, bool verbose = false) {
    // Safety check
    if (!ahci_base || !current_directory_cluster) {
        wm.print_to_focused("ERROR: Filesystem not initialized!");
        return;
    }
    
    wm.print_to_focused("=====================================");
    wm.print_to_focused("    DISK CHECK UTILITY (CHKDSK)     ");
    wm.print_to_focused("=====================================");
    
    if (fix) {
        wm.print_to_focused("\nMode: FIX ERRORS (writing enabled)");
    } else {
        wm.print_to_focused("\nMode: READ-ONLY (no changes)");
    }
    
    ChkdskStats stats;
    memset(&stats, 0, sizeof(stats));
    
    // SAFETY: Check for valid values
    if (bpb.sec_per_clus == 0) {
        wm.print_to_focused("ERROR: Invalid cluster size!");
        return;
    }
    
    if (bpb.tot_sec32 <= bpb.rsvd_sec_cnt + (uint32_t)bpb.num_fats * bpb.fat_sz32) {
        wm.print_to_focused("ERROR: Invalid disk geometry!");
        return;
    }
    
    stats.total_clusters = fat32_data_sectors() / bpb.sec_per_clus;
    
    // SAFETY: Prevent division by zero
    if (stats.total_clusters == 0) {
        wm.print_to_focused("ERROR: No data clusters available!");
        return;
    }
    
    char msg[100];
    snprintf(msg, 100, "\nVolume size: %d sectors (%d MB)", 
             bpb.tot_sec32, (bpb.tot_sec32 * SECTOR_SIZE) / (1024 * 1024));
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "Cluster size: %d KB", (bpb.sec_per_clus * SECTOR_SIZE) / 1024);
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "Total clusters: %d", stats.total_clusters);
    wm.print_to_focused(msg);
    
    wm.print_to_focused("\n=== Phase 1: Checking boot sector ===");
    
    if (strncmp(bpb.fil_sys_type, "FAT32   ", 8) != 0) {
        wm.print_to_focused("ERROR: Invalid filesystem type!");
        return;
    }
    wm.print_to_focused("OK: Boot sector is valid");
    
    // Comment out FAT consistency check for now (might be causing issue)
    // check_fat_consistency(stats, fix);
    
    wm.print_to_focused("\n=== Phase 2: Scanning directories ===");
    
    // SAFETY: Pre-flight the cluster bitmap allocation.
    //
    // init_cluster_bitmap() needs 1 bit per cluster on the volume. The
    // check below (`if (!cluster_bitmap)`) looks like it handles an
    // allocation failure, but it never actually can: `operator new[]`
    // in this kernel does not return null on failure — it calls
    // oom_halt(), which paints an error to the screen and then HALTS
    // THE WHOLE KERNEL (cli; hlt loop). So on any volume big enough
    // (or with corrupt/garbage BPB geometry — easy to end up with after
    // the disk has been repartitioned/reformatted by another OS) that
    // the bitmap doesn't fit in whatever's left of the heap, chkdsk
    // didn't fail cleanly — it froze the entire machine. That's the
    // "chkdsk causes an OOM crash" bug.
    //
    // Fix: compute the bitmap size up front and compare it against
    // g_allocator.total_free() (with a safety margin for everything
    // else still running — windows, the terminal's own buffers, other
    // in-flight FAT32 operations) *before* calling operator new. If it
    // won't fit, report a normal chkdsk error and return instead of
    // ever reaching the allocation that would halt the kernel.
    {
        uint64_t clusters_for_bitmap = (uint64_t)fat32_max_clusters();
        uint64_t bitmap_bytes = ((clusters_for_bitmap + 31) / 32) * sizeof(uint32_t);
        const uint64_t SAFETY_MARGIN = 4 * 1024 * 1024; // leave 4MB free for everything else
        uint64_t free_now = (uint64_t)g_allocator.total_free();

        if (bitmap_bytes + SAFETY_MARGIN > free_now) {
            // NOTE: this kernel's snprintf only implements %d/%s/%c (no
            // %u/%llu/%x), so keep everything as plain `int` KB counts.
            // Both values are bounded well within INT32_MAX for any
            // heap size this kernel actually uses (tens of MB), even
            // for a maximally-corrupt uint32_t cluster count.
            int needed_kb = (int)(bitmap_bytes / 1024);
            int free_kb   = (int)(free_now / 1024);
            snprintf(msg, 100, "ERROR: Volume too large for chkdsk (needs %d KB,", needed_kb);
            wm.print_to_focused(msg);
            snprintf(msg, 100, "       only %d KB free). Aborting safely.", free_kb);
            wm.print_to_focused(msg);
            snprintf(msg, 100, "Cluster size: %d KB -- a volume this large with clusters this",
                     (bpb.sec_per_clus * SECTOR_SIZE) / 1024);
            wm.print_to_focused(msg);
            wm.print_to_focused("small has far more clusters than chkdsk's memory budget allows.");
            wm.print_to_focused("If this volume wasn't formatted with this OS's current 'formatfs'");
            wm.print_to_focused("(which now scales cluster size to the real disk size), reformatting");
            wm.print_to_focused("it will very likely bring the cluster count back into range.");
            return;
        }
    }

    // SAFETY: Initialize bitmap
    init_cluster_bitmap();
    if (!cluster_bitmap) {
        wm.print_to_focused("ERROR: Failed to allocate cluster bitmap!");
        return;
    }
    
    mark_cluster_used(0);
    mark_cluster_used(1);
    
    // SAFETY: Check root cluster validity
    if (bpb.root_clus < 2 || bpb.root_clus >= FAT_END_OF_CHAIN) {
        wm.print_to_focused("ERROR: Invalid root cluster!");
        if (cluster_bitmap) {
            delete[] cluster_bitmap;
            cluster_bitmap = nullptr;
        }
        return;
    }
    
    mark_cluster_used(bpb.root_clus);
    
    wm.print_to_focused("Scanning root directory...");
    
    // SAFETY: Limit recursion depth to prevent stack overflow
    scan_directory(bpb.root_clus, stats, fix, 0);
    
    wm.print_to_focused("\n=== Phase 3: Statistics ===");
    
    // Simple stats without lost cluster scan (can add back later)
    for (uint32_t i = 2; i < stats.total_clusters + 2; i++) {
        uint32_t entry = read_fat_entry(i);
        if (entry == FAT_FREE_CLUSTER) {
            stats.free_clusters++;
        } else if (entry >= 0x0FFFFFF7) {
            stats.bad_clusters++;
        } else {
            stats.used_clusters++;
        }
    }
    
    wm.print_to_focused("\n=====================================");
    wm.print_to_focused("         CHKDSK RESULTS              ");
    wm.print_to_focused("=====================================");
    
    snprintf(msg, 100, "Directories checked:  %d", stats.directories_checked);
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "Files checked:        %d", stats.files_checked);
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "\nTotal clusters:       %d", stats.total_clusters);
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "Used clusters:        %d (%d%%)", 
             stats.used_clusters, (stats.used_clusters * 100) / stats.total_clusters);
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "Free clusters:        %d (%d%%)", 
             stats.free_clusters, (stats.free_clusters * 100) / stats.total_clusters);
    wm.print_to_focused(msg);
    
    snprintf(msg, 100, "Bad clusters:         %d", stats.bad_clusters);
    wm.print_to_focused(msg);
    
    wm.print_to_focused("");
    snprintf(msg, 100, "Errors found:         %d", stats.errors_found);
    wm.print_to_focused(msg);
    
    if (fix && stats.errors_fixed > 0) {
        snprintf(msg, 100, "Errors fixed:         %d", stats.errors_fixed);
        wm.print_to_focused(msg);
    }
    
    if (stats.errors_found == 0) {
        wm.print_to_focused("\nNo errors found. Disk is healthy!");
    }
    
    // Cleanup
    if (cluster_bitmap) {
        delete[] cluster_bitmap;
        cluster_bitmap = nullptr;
    }
    
    wm.print_to_focused("=====================================");
}


void chkdsk_full_scan(bool fix = false) {
    wm.print_to_focused("\n=== Phase 5: Scanning for bad sectors ===");
    wm.print_to_focused("This may take several minutes...");
    
    uint8_t* test_buffer = new uint8_t[SECTOR_SIZE];
    uint32_t bad_sectors = 0;
    uint32_t total_sectors = bpb.tot_sec32;
    
    for (uint32_t sector = 0; sector < total_sectors; sector += 1) {
        if (read_write_sectors(g_ahci_port, sector, 1, false, test_buffer) != 0) {
            bad_sectors++;
            
            char msg[80];
            snprintf(msg, 80, "  Bad sector detected at LBA %d", sector);
            wm.print_to_focused(msg);
            
            if (sector >= data_start_sector) {
                uint32_t cluster = ((sector - data_start_sector) / bpb.sec_per_clus) + 2;
                if (fix && is_valid_cluster(cluster)) {
                    write_fat_entry(cluster, 0x0FFFFFF7);
                    wm.print_to_focused("  FIXED: Marked cluster as bad in FAT");
                }
            }
        }
        
        if ((sector / 1000) % 10 == 0 && sector > 0) {
            char progress[60];
            snprintf(progress, 60, "Progress: %d%% (%d/%d sectors)", 
                     (sector * 100) / total_sectors, sector, total_sectors);
            wm.print_to_focused(progress);
        }
    }
    
    delete[] test_buffer;
    
    char summary[80];
    snprintf(summary, 80, "\nBad sector scan complete: %d bad sectors found", bad_sectors);
    wm.print_to_focused(summary);
}


#include <cstdarg>    // For va_list in printf

// =============================================================================
// SECTION 6: SELF-HOSTED C COMPILER
// =============================================================================

// Forward declarations consumed by the command shell
extern "C" void cmd_compile(uint64_t ahci_base, int port, const char* filename);
extern "C" void cmd_run(uint64_t ahci_base, int port, const char* filename);
extern "C" void cmd_exec(const char* code_text);
struct HardwareDevice {
    uint32_t vendor_id;
    uint32_t device_id;
    uint64_t base_address;
    uint64_t size;
    uint32_t device_type;  // 0=Unknown, 1=Storage, 2=Network, 3=Graphics, 4=Audio, 5=USB
    char description[64];
};
// --- Global Hardware Registry Definition ---
const int MAX_HARDWARE_DEVICES = 32; // Define the constant
HardwareDevice hardware_registry[MAX_HARDWARE_DEVICES];
int hardware_count = 0;

// Define shell parts variables (as declared extern in the header)
// These will be populated by the terminal handler in kernel.cpp
char* parts[32];
int   part_count = 0;


// ---- tiny helpers ----
static inline int tcc_is_digit(char c){ return c>='0' && c<='9'; }
static inline int tcc_is_alpha(char c){ return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'; }
static inline int tcc_is_alnum(char c){ return tcc_is_alpha(c)||tcc_is_digit(c); }
static inline int tcc_strlen(const char* s){ int n=0; while(s && s[n]) ++n; return n; }

// ============================================================
// Console and Terminal I/O Functions
// ============================================================
void console_putc(char c) {
    wm.put_char_to_focused(c);
}
// VGA Text Mode Buffer (typically at 0xB8000)
static volatile char* const VGA_BUFFER = (volatile char* const)0xB8000;
static int vga_row = 0;
static int vga_col = 0;
static const int VGA_WIDTH = 80;
static const int VGA_HEIGHT = 23;
void vga_print_char(char c) {
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
        if (vga_row >= VGA_HEIGHT) {
            vga_row = VGA_HEIGHT - 1;
            // Scroll VGA buffer up
            for (int row = 0; row < VGA_HEIGHT - 1; row++) {
                for (int col = 0; col < VGA_WIDTH; col++) {
                    int src_idx = ((row + 1) * VGA_WIDTH + col) * 2;
                    int dst_idx = (row * VGA_WIDTH + col) * 2;
                    VGA_BUFFER[dst_idx] = VGA_BUFFER[src_idx];
                    VGA_BUFFER[dst_idx + 1] = VGA_BUFFER[src_idx + 1];
                }
            }
            // Clear last line
            for (int col = 0; col < VGA_WIDTH; col++) {
                int idx = ((VGA_HEIGHT - 1) * VGA_WIDTH + col) * 2;
                VGA_BUFFER[idx] = ' ';
                VGA_BUFFER[idx + 1] = 0x07;
            }
        }
    } else if (c >= 32 && c < 127) {
        int index = (vga_row * VGA_WIDTH + vga_col) * 2;
        VGA_BUFFER[index] = c;
        VGA_BUFFER[index + 1] = 0x07;
        vga_col++;
        if (vga_col >= VGA_WIDTH) {
            vga_col = 0;
            vga_row++;
            if (vga_row >= VGA_HEIGHT) {
                vga_row = VGA_HEIGHT - 1;
                // Scroll VGA buffer up
                for (int row = 0; row < VGA_HEIGHT - 1; row++) {
                    for (int col = 0; col < VGA_WIDTH; col++) {
                        int src_idx = ((row + 1) * VGA_WIDTH + col) * 2;
                        int dst_idx = (row * VGA_WIDTH + col) * 2;
                        VGA_BUFFER[dst_idx] = VGA_BUFFER[src_idx];
                        VGA_BUFFER[dst_idx + 1] = VGA_BUFFER[src_idx + 1];
                    }
                }
                // Clear last line
                for (int col = 0; col < VGA_WIDTH; col++) {
                    int idx = ((VGA_HEIGHT - 1) * VGA_WIDTH + col) * 2;
                    VGA_BUFFER[idx] = ' ';
                    VGA_BUFFER[idx + 1] = 0x07;
                }
            }
        }
    }
}

void vga_print(const char* str) {
    if (!str) return;
    while (*str) {
        vga_print_char(*str);
        str++;
    }
}

// Route to window if available, otherwise VGA
void console_print_char(char c) {
    int num_wins = wm.get_num_windows();
    int focused = wm.get_focused_idx();
    if (num_wins > 0 && focused >= 0 && focused < num_wins) {
        Window* win = wm.get_window(focused);
        if (win) {
            char buf[2] = {c, 0};
            win->console_print(buf);
        }
    } else {
        vga_print_char(c);
    }
}

void console_print(const char* str) {
    if (!str) return;
    int num_wins = wm.get_num_windows();
    int focused = wm.get_focused_idx();
    if (num_wins > 0 && focused >= 0 && focused < num_wins) {
        Window* win = wm.get_window(focused);
        if (win) {
            win->console_print(str);
        }
    } else {
        vga_print(str);
    }
}

// CORRECTED: Non-blocking get_char with fallback
static char pending_char = 0;

char get_char() {
    // Check if we have a pending character from previous call
    if (pending_char != 0) {
        char c = pending_char;
        pending_char = 0;
        return c;
    }

    // Non-blocking read from keyboard
    while (1) {
        uint8_t status = inb(0x64);
        if (status & 0x01) { // Data available
            uint8_t scancode = inb(0x60);

            // Simple scancode to ASCII conversion (US keyboard layout)
            static const char scancode_map[] = {
                0,   27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
                'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 'a', 's',
                'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
                'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' '
            };

            if (scancode < sizeof(scancode_map)) {
                char c = scancode_map[scancode];
                if (c != 0) {
                    vga_print_char(c);
                    return c;
                }
            }
        } else {
            // No data available - return a null character
            // The caller should handle this and retry if needed
            return 0;
        }
    }
}


// ============================================================
// Integer Conversion Functions
// ============================================================

void int_to_string(int value, char* buffer) {
    if (!buffer) return;
    
    if (value == 0) {
        buffer[0] = '0';
        buffer[1] = 0;
        return;
    }
    
    int negative = value < 0;
    if (negative) value = -value;
    
    int i = 0;
    char temp[16];
    
    while (value > 0) {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    }
    
    int j = 0;
    if (negative) buffer[j++] = '-';
    
    while (i > 0) {
        buffer[j++] = temp[--i];
    }
    
    buffer[j] = 0;
}


// ============================================================
// File I/O Functions (FAT32 Support)
// ============================================================

// Simplified file buffer for storage
static char file_buffer[4096]; // 4KB — stub buffer (real I/O goes through heap)


// ============================================================
// Memory Management (new/delete operators)
// ============================================================

// (heap managed by g_allocator via kernel_heap[] above)


void simple_strcpy(char* dest, const char* src) {
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';
}

// Bounded copy for fixed-size stack/struct buffers. simple_strcpy() above
// is unbounded (identical hazard to libc strcpy) -- fine when the source
// is already known to fit, but the compiler front-end (08_...) copies
// lexer tokens (up to ~63 chars, see TTok::v[256] in that file) into
// 32-byte identifier buffers with plain simple_strcpy(). This kernel is
// built with -fno-stack-protector, so an identifier over 31 characters
// in a compiled source file silently smashed the compiler's own stack --
// reachable just by running the OS's own `compile` command on a crafted
// .cpp file. Truncates safely instead of overflowing; always
// NUL-terminates within destsize (destsize must be >= 1).
void simple_strcpy_bounded(char* dest, const char* src, int destsize) {
    int i = 0;
    for (; i < destsize - 1 && src[i]; i++) dest[i] = src[i];
    dest[i] = '\0';
}

int simple_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

void* simple_memcpy(void* dest, const void* src, int n) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}
// Basic printf implementation
void printf(const char* format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[256]; // A buffer to hold consecutive characters
    int buffer_index = 0;

    while (*format != '\0') {
        if (*format == '%') {
            // If there's anything in the buffer, print it first
            if (buffer_index > 0) {
                buffer[buffer_index] = '\0';
                console_print(buffer);
                buffer_index = 0; // Reset buffer
            }

            format++; // Move past the '%'
            if (*format == 'd') {
                int i = va_arg(args, int);
                char num_buf[12];
                int_to_string(i, num_buf);
                console_print(num_buf);
            } else if (*format == 's') {
                char* s = va_arg(args, char*);
                console_print(s);
            } else if (*format == 'c') {
                char c = (char)va_arg(args, int);
                char str[2] = {c, 0};
                console_print(str);
            } else { // Handles %% and unknown specifiers
                console_print_char('%');
                console_print_char(*format);
            }
        } else {
            // Add the character to our buffer
            if (buffer_index < 255) {
                buffer[buffer_index++] = *format;
            }
        }
        format++;
    }

    // Print any remaining characters in the buffer at the end
    if (buffer_index > 0) {
        buffer[buffer_index] = '\0';
        console_print(buffer);
    }

    va_end(args);
}


// Helper functions for hex conversion and PCI access
static void uint32_to_hex_string(uint32_t value, char* buffer) {
    const char hex_chars[] = "0123456789ABCDEF";
    for(int i = 7; i >= 0; i--) {
        buffer[7-i] = hex_chars[(value >> (i*4)) & 0xF];
    }
    buffer[8] = 0;
}

static void uint64_to_hex_string(uint64_t value, char* buffer) {
    const char hex_chars[] = "0123456789ABCDEF";
    for(int i = 15; i >= 0; i--) {
        buffer[15-i] = hex_chars[(value >> (i*4)) & 0xF];
    }
    buffer[16] = 0;
}

// Simple PCI configuration space access
static uint32_t pci_config_read_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)device << 11) |
                       ((uint32_t)function << 8) | (offset & 0xFC);

    // Write address to CONFIG_ADDRESS (0xCF8)
    asm volatile("outl %0, %w1" : : "a"(address), "Nd"(0xCF8) : "memory");

    // Read data from CONFIG_DATA (0xCFC)
    uint32_t result;
    asm volatile("inl %w1, %0" : "=a"(result) : "Nd"(0xCFC) : "memory");

    return result;
}



// Global hardware_registry and hardware_count are defined at the top of the file.

// More comprehensive PCI class codes
static const char* get_pci_class_name(uint8_t base_class, uint8_t sub_class) {
    switch (base_class) {
        case 0x00: return "Unclassified";
        case 0x01:
            switch (sub_class) {
                case 0x00: return "SCSI Controller";
                case 0x01: return "IDE Controller";
                case 0x02: return "Floppy Controller";
                case 0x03: return "IPI Controller";
                case 0x04: return "RAID Controller";
                case 0x05: return "ATA Controller";
                case 0x06: return "SATA Controller";
                case 0x07: return "SAS Controller";
                case 0x08: return "NVMe Controller";
                default: return "Storage Controller";
            }
        case 0x02: return "Network Controller";
        case 0x03:
            switch (sub_class) {
                case 0x00: return "VGA Controller";
                case 0x01: return "XGA Controller";
                case 0x02: return "3D Controller";
                default: return "Display Controller";
            }
        case 0x04: return "Multimedia Controller";
        case 0x05: return "Memory Controller";
        case 0x06: return "Bridge Device";
        case 0x07: return "Communication Controller";
        case 0x08: return "System Peripheral";
        case 0x09: return "Input Device";
        case 0x0A: return "Docking Station";
        case 0x0B: return "Processor";
        case 0x0C:
            switch (sub_class) {
                case 0x00: return "FireWire Controller";
                case 0x01: return "ACCESS Bus";
                case 0x02: return "SSA";
                case 0x03: return "USB Controller";
                case 0x04: return "Fibre Channel";
                case 0x05: return "SMBus";
                default: return "Serial Bus Controller";
            }
        case 0x0D: return "Wireless Controller";
        case 0x0E: return "Intelligent Controller";
        case 0x0F: return "Satellite Controller";
        case 0x10: return "Encryption Controller";
        case 0x11: return "Signal Processing Controller";
        default: return "Unknown Device";
    }
}

// Improved PCI device discovery
static void discover_pci_devices() {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t function = 0; function < 8; function++) {
                uint32_t vendor_device = pci_config_read_dword(bus, device, function, 0);
                if ((vendor_device & 0xFFFF) == 0xFFFF) continue;

                if (hardware_count >= MAX_HARDWARE_DEVICES) return;

                HardwareDevice& dev = hardware_registry[hardware_count];
                dev.vendor_id = vendor_device & 0xFFFF;
                dev.device_id = (vendor_device >> 16) & 0xFFFF;

                // Read class code
                uint32_t class_code = pci_config_read_dword(bus, device, function, 0x08);
                uint8_t base_class = (class_code >> 24) & 0xFF;
                uint8_t sub_class = (class_code >> 16) & 0xFF;

                // Map to device type
                switch (base_class) {
                    case 0x01: dev.device_type = 1; break; // Storage
                    case 0x02: dev.device_type = 2; break; // Network
                    case 0x03: dev.device_type = 3; break; // Graphics
                    case 0x04: dev.device_type = 4; break; // Audio
                    case 0x0C:
                        dev.device_type = (sub_class == 0x03) ? 5 : 0; // USB or other
                        break;
                    default: dev.device_type = 0; break;
                }

                // Get description
                const char* desc = get_pci_class_name(base_class, sub_class);
                strncpy(dev.description, desc, 63);
                dev.description[63] = '\0';

                // Read BAR0 for base address (handle both 32-bit and 64-bit BARs)
                uint32_t bar0 = pci_config_read_dword(bus, device, function, 0x10);
                if (bar0 & 0x1) {
                    // I/O port
                    dev.base_address = bar0 & 0xFFFFFFFC;
                    dev.size = 0x100;
                } else {
                    // Memory mapped
                    dev.base_address = bar0 & 0xFFFFFFF0;
                    
                    // Check if 64-bit BAR
                    if ((bar0 & 0x6) == 0x4) {
                        uint32_t bar1 = pci_config_read_dword(bus, device, function, 0x14);
                        dev.base_address |= ((uint64_t)bar1 << 32);
                    }
                    
                    // Try to determine size by writing all 1s and reading back
                    pci_config_read_dword(bus, device, function, 0x04); // Save command reg
                    uint32_t orig_bar = bar0;
                    
                    outl(0xCF8, 0x80000000 | ((uint32_t)bus << 16) | 
                         ((uint32_t)device << 11) | ((uint32_t)function << 8) | 0x10);
                    outl(0xCFC, 0xFFFFFFFF);
                    uint32_t size_bar = inl(0xCFC);
                    
                    // Restore original BAR
                    outl(0xCF8, 0x80000000 | ((uint32_t)bus << 16) | 
                         ((uint32_t)device << 11) | ((uint32_t)function << 8) | 0x10);
                    outl(0xCFC, orig_bar);
                    
                    if (size_bar != 0 && size_bar != 0xFFFFFFFF) {
                        size_bar &= 0xFFFFFFF0;
                        dev.size = ~size_bar + 1;
                    } else {
                        dev.size = 0x1000; // Default to 4KB
                    }
                }

                hardware_count++;

                if (function == 0) {
                    uint8_t header_type = (class_code >> 16) & 0xFF;
                    if (!(header_type & 0x80)) {
                        break; // Single function device
                    }
                }
            }
        }
    }
}


static void discover_memory_regions() {
    // Add known memory regions
    if (hardware_count < MAX_HARDWARE_DEVICES) {
        HardwareDevice& dev = hardware_registry[hardware_count];
        dev.vendor_id = 0x0000;
        dev.device_id = 0x0001;
        dev.base_address = 0xB8000; // VGA text mode buffer
        dev.size = 0x8000;
        dev.device_type = 3;
        simple_strcpy(dev.description, "VGA Text Buffer");
        hardware_count++;
    }

    if (hardware_count < MAX_HARDWARE_DEVICES) {
        HardwareDevice& dev = hardware_registry[hardware_count];
        dev.vendor_id = 0x0000;
        dev.device_id = 0x0002;
        dev.base_address = 0xA0000; // VGA graphics buffer
        dev.size = 0x20000;
        dev.device_type = 3;
        simple_strcpy(dev.description, "VGA Graphics Buffer");
        hardware_count++;
    }
}

static int scan_hardware() {
    hardware_count = 0;
    discover_pci_devices();
    discover_memory_regions();
    return hardware_count;
}

// Safety check for MMIO access
static bool is_safe_mmio_address(uint64_t addr, uint64_t size) {
    // Check if address falls within any known device range
    for (int i = 0; i < hardware_count; i++) {
        const HardwareDevice& dev = hardware_registry[i];
        if (addr >= dev.base_address &&
            addr + size <= dev.base_address + dev.size) {
            return true;
        }
    }

    // Allow access to standard VGA and system areas even if not enumerated
    if (addr >= 0xA0000 && addr < 0x100000) return true; // VGA/BIOS area
    if (addr >= 0xB8000 && addr < 0xC0000) return true; // VGA text buffer
    if (addr >= 0x3C0 && addr < 0x3E0) return true;     // VGA registers
    if (addr >= 0x60 && addr < 0x70) return true;       // Keyboard controller

    return false;
}
