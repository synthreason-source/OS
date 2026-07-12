#pragma once
// 01_fs_encryption.h
// XOR-based filesystem encryption layer sitting under the FAT32 driver.
// Extracted from kernel.cpp (original lines 461-897) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.

static uint8_t g_fs_xor_key[64]        = {0};  // 64-byte keystream
static int     g_fs_xor_key_len        = 0;

// =============================================================================
// FILESYSTEM XOR ENCRYPTION LAYER
// =============================================================================

// Derive a 64-byte keystream from password using FNV-1a mixing
static void derive_xor_key(const char* password, uint8_t key_out[64], int* key_len_out) {
    uint32_t h = 2166136261u;
    const char* p = password;
    while (*p) {
        h ^= (uint8_t)*p++;
        h *= 16777619u;
    }

    // Expand hash into 64 bytes by re-mixing with position
    for (int i = 0; i < 64; i++) {
        h ^= (uint32_t)i * 2654435761u;
        h *= 16777619u;
        key_out[i] = (uint8_t)(h ^ (h >> 16));
    }
    *key_len_out = 64;
}

// XOR a 512-byte sector buffer in place.
// LBA is mixed into each block so identical plaintext sectors at different
// locations produce different ciphertext (poor-man's sector tweak).
static void xor_sector(uint8_t* buf, uint64_t lba) {
    if (!g_fs_encryption_enabled || g_fs_xor_key_len == 0) return;

    // Build a per-sector tweak from the LBA
    uint8_t tweak[8];
    for (int i = 0; i < 8; i++) tweak[i] = (uint8_t)(lba >> (i * 8));

    for (int i = 0; i < SECTOR_SIZE; i++) {
        uint8_t k = g_fs_xor_key[i % g_fs_xor_key_len];
        uint8_t t = tweak[i % 8];
        buf[i] ^= (k ^ t);
    }
}

// Call after successful unlock to arm the encryption layer
static void fs_crypto_init(const char* password) {
    derive_xor_key(password, g_fs_xor_key, &g_fs_xor_key_len);
    g_fs_encryption_enabled = true;
}

// Call on lock/disk-switch to wipe key material from memory
static void fs_crypto_clear() {
    g_fs_encryption_enabled = false;
    memset(g_fs_xor_key, 0, sizeof(g_fs_xor_key));
    g_fs_xor_key_len = 0;
}
// --- Global State Variables ---
// Moved here to be visible to all classes
static volatile uint32_t g_timer_ticks = 0;

// --- Forward Declarations ---
class Window;
class TerminalWindow;
class FileExplorerWindow;

// Kernel Entry
extern "C" void kernel_main(uint32_t magic, uint32_t multiboot_addr);

// App Launchers
void launch_new_terminal();
void launch_new_explorer();

// FAT32 Function Prototypes
int fat32_write_file(const char* filename, const void* data, uint32_t size);
int fat32_remove_file(const char* filename);
char* fat32_read_file_as_string(const char* filename);
void fat32_list_files();
bool fat32_init();
void fat32_get_fne_from_entry(fat_dir_entry_t* entry, char* out); // New helper
int fat32_stat_file(const char* filename, uint32_t* size_out); // Guest disk wrapper helper (bochs_glue.cpp)
// --- Minimal Standard Library ---
size_t strlen(const char* str) { size_t len = 0; while (str[len]) len++; return len; }
int memcmp(const void* ptr1, const void* ptr2, size_t n) { const uint8_t* p1 = (const uint8_t*)ptr1; const uint8_t* p2 = (const uint8_t*)ptr2; for(size_t i=0; i<n; ++i) if(p1[i] != p2[i]) return p1[i] - p2[i]; return 0; }
int strcmp(const char* s1, const char* s2) { while(*s1 && (*s1 == *s2)) { s1++; s2++; } return *(const unsigned char*)s1 - *(const unsigned char*)s2; }
int strncmp(const char* s1, const char* s2, size_t n) { if (n == 0) return 0; do { if (*s1 != *s2++) return *(unsigned const char*)s1 - *(unsigned const char*)--s2; if (*s1++ == 0) break; } while (--n != 0); return 0; }
char* strchr(const char* s, int c) { while (*s != (char)c) if (!*s++) return nullptr; return (char*)s; }
char* strrchr(const char* s, int c) { const char* last = nullptr; do { if (*s == (char)c) last = s; } while (*s++); return (char*)last; } // New for finding extensions
char* strcpy(char *dest, const char *src) { char *ret = dest; while ((*dest++ = *src++)); return ret; }
char* strncpy(char* dest, const char* src, size_t n) { size_t i; for (i = 0; i < n && src[i] != '\0'; i++) dest[i] = src[i]; for ( ; i < n; i++) dest[i] = '\0'; return dest; }
char* strcat(char* dest, const char* src) {
    char* ptr = dest;
    while (*ptr != '\0') { ptr++; }
    while (*src != '\0') { *ptr = *src; ptr++; src++; }
    *ptr = '\0';
    return dest;
}
char* strncat(char *dest, const char *src, size_t n) {
    size_t dest_len = strlen(dest);
    size_t i;
    for (i = 0 ; i < n && src[i] != '\0' ; i++)
        dest[dest_len + i] = src[i];
    dest[dest_len + i] = '\0';
    return dest;
}
int simple_atoi(const char* str) { int res = 0; while(*str >= '0' && *str <= '9') { res = res * 10 + (*str - '0'); str++; } return res; }
const char* strstr(const char* haystack, const char* needle) {
    if (!*needle) return haystack;
    const char* p1 = haystack;
    while (*p1) {
        const char* p1_begin = p1;
        const char* p2 = needle;
        while (*p1 && *p2 && *p1 == *p2) { p1++; p2++; }
        if (!*p2) { return p1_begin; }
        p1 = p1_begin + 1;
    }
    return nullptr;
}
int snprintf(char* buffer, size_t size, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char* buf = buffer;
    char* end = buffer + size - 1;
    while (*fmt && buf < end) {
        if (*fmt == '%') {
            fmt++;
            if (*fmt == 'd') {
                int val = va_arg(args, int);
                char tmp[32];
                char* t = tmp + 31; *t = '\0';
                bool neg = val < 0;
                if(neg) val = -val;
                if(val == 0) *--t = '0';
                else while(val > 0) { *--t = '0' + val % 10; val /= 10; }
                if (neg) *--t = '-';
                while (*t && buf < end) *buf++ = *t++;
            } else if (*fmt == 's') {
                const char* s = va_arg(args, const char*);
                while (*s && buf < end) *buf++ = *s++;
            } else if (*fmt == 'c') {
                char c = (char)va_arg(args, int);
                if (buf < end) *buf++ = c;
            } else {
                 if (buf < end) *buf++ = *fmt;
            }
        } else {
            *buf++ = *fmt;
        }
        fmt++;
    }
    *buf = '\0';
    va_end(args);
    return buf - buffer;
}

// --- Basic Memory Allocator ---
// Single 32MB global heap in BSS (not stack!) — enough for BusyBox + 4 ELF procs + FAT32 + backbuffer
/* 16 MB heap — keeps total BSS under ~20 MB so GRUB can zero it reliably.
   100 MB caused bochs init_memory to corrupt/loop because GRUB only zeroes
   ~12–24 MB of BSS before jumping to _start; FreeListAllocator nodes beyond
   that boundary contained garbage.  Budget: BusyBox ramdisk (~2 MB mapped
   read-only), 4 ELF slabs × ~300 KB, backbuffer 3 MB, FAT32 sector
   buffers, Bochs init_memory internals (~2 MB).  16 MB covers all of that
   with room to spare and keeps total BSS well within GRUB's zeroing window. */
static uint8_t kernel_heap[64 * 1024 * 1024];
static size_t heap_ptr = 0;
void* operator new(size_t, void* p) { return p; }

// Pulled forward from below so oom_halt() (which lives in this file before
// the original include site) can paint glyphs to the live framebuffer.
#include "../font.h"

// Forward decl of the framebuffer descriptor so oom_halt() can paint to the
// live framebuffer below. Real definition (with initializer) is further down.
struct FramebufferInfo { uint32_t* ptr; uint32_t width, height, pitch; };
extern FramebufferInfo fb_info;

class FreeListAllocator {
public:
    struct FreeBlock {
        size_t size;
        FreeBlock* next;
    };

private:
    FreeBlock* freeListHead;

public:
    FreeListAllocator() : freeListHead(nullptr) {}

    void init(void* heapStart, size_t heapSize) {
        if (!heapStart || heapSize < sizeof(FreeBlock)) {
            return;
        }
        freeListHead = static_cast<FreeBlock*>(heapStart);
        freeListHead->size = heapSize;
        freeListHead->next = nullptr;
    }

    void* allocate(size_t size) {
        size_t required_size = (size + sizeof(size_t) + (alignof(FreeBlock) - 1)) & ~(alignof(FreeBlock) - 1);
        if (required_size < sizeof(FreeBlock)) {
            required_size = sizeof(FreeBlock);
        }

        FreeBlock* prev = nullptr;
        FreeBlock* current = freeListHead;
        while (current) {
            if (current->size >= required_size) {
                if (current->size >= required_size + sizeof(FreeBlock)) {
                    FreeBlock* newBlock = (FreeBlock*)((char*)current + required_size);
                    newBlock->size = current->size - required_size;
                    newBlock->next = current->next;

                    if (prev) {
                        prev->next = newBlock;
                    } else {
                        freeListHead = newBlock;
                    }
                } else {
                    required_size = current->size;
                    if (prev) {
                        prev->next = current->next;
                    } else {
                        freeListHead = current->next;
                    }
                }
                
                *(size_t*)current = required_size;
                return (char*)current + sizeof(size_t);
            }
            prev = current;
            current = current->next;
        }
        return nullptr;
    }

    void deallocate(void* ptr) {
        if (!ptr) return;

        FreeBlock* block_to_free = (FreeBlock*)((char*)ptr - sizeof(size_t));
        size_t block_size = *(size_t*)block_to_free;
        block_to_free->size = block_size;

        FreeBlock* prev = nullptr;
        FreeBlock* current = freeListHead;
        while (current && current < block_to_free) {
            prev = current;
            current = current->next;
        }

        if (prev) {
            prev->next = block_to_free;
        } else {
            freeListHead = block_to_free;
        }
        block_to_free->next = current;

        if (block_to_free->next && (char*)block_to_free + block_to_free->size == (char*)block_to_free->next) {
            block_to_free->size += block_to_free->next->size;
            block_to_free->next = block_to_free->next->next;
        }

        if (prev && (char*)prev + prev->size == (char*)block_to_free) {
            prev->size += block_to_free->size;
            prev->next = block_to_free->next;
        }
    }

    // Sum of all free blocks currently on the free list. Used by callers
    // (e.g. chkdsk) that are about to request a large allocation and want
    // to fail gracefully instead of triggering oom_halt(), which freezes
    // the whole kernel rather than just the requesting operation.
    size_t total_free() const {
        size_t sum = 0;
        for (FreeBlock* cur = freeListHead; cur; cur = cur->next) sum += cur->size;
        return sum;
    }
};

static FreeListAllocator g_allocator;

// Write OOM message directly to VGA text buffer AND to the live framebuffer.
// VGA text alone is invisible in graphics mode unless draw_vga_overlay() runs
// — but oom_halt() is reached from inside an allocation site that's about to
// halt the kernel, so the main loop never paints again. Painting straight to
// fb_info.ptr (live, NOT backbuffer) bypasses the swap_buffers cycle so the
// message is visible immediately even with a dead main loop.
static void oom_halt(size_t size) {
    // ── 1. VGA text plane (forensic, visible only if overlay paints later) ──
    volatile char* vga = (volatile char*)0xB8000;
    const char* msg = "OOM HALT";
    for (int i = 0; msg[i]; i++) { vga[i*2] = msg[i]; vga[i*2+1] = 0x4F; }
    // Print size in decimal after the message
    char buf[16]; int n = 0, s = (int)size;
    if (s == 0) buf[n++] = '0';
    else { int tmp = s; int d = 1; while (tmp >= 10) { tmp /= 10; d++; }
           for (int i = d-1; i >= 0; i--) { buf[i] = '0' + s%10; s/=10; n++; } }
    buf[n] = 0;
    int off = 8;
    vga[off*2]=' '; vga[off*2+1]=0x4F; off++;
    for (int i = 0; i < n; i++) { vga[(off+i)*2]=buf[i]; vga[(off+i)*2+1]=0x4F; }

    // ── 2. Live framebuffer (visible immediately, survives a hung main loop) ──
    if (fb_info.ptr) {
        // Bright red bar across rows 24..47 — distinct from host_fault_handler's
        // bar (rows 0..23) so we can tell OOM apart from CPU faults at a glance.
        int bar_y0 = 24;
        int bar_h  = 24;
        if (bar_y0 + bar_h > (int)fb_info.height) bar_h = fb_info.height - bar_y0;
        if (bar_h > 0) {
            for (int y = bar_y0; y < bar_y0 + bar_h; ++y) {
                uint32_t* row = &fb_info.ptr[y * (fb_info.pitch / 4)];
                for (uint32_t x = 0; x < fb_info.width; ++x) row[x] = 0xC00000u;
            }
        }
        auto put_glyph = [](char ch, int x0, int y0, uint32_t color) {
            if ((unsigned char)ch > 127) return;
            if (x0 + 8 > (int)fb_info.width)  return;
            if (y0 + 8 > (int)fb_info.height) return;
            const uint8_t* glyph = font + (int)ch * 8;
            for (int yy = 0; yy < 8; ++yy) {
                uint32_t* row = &fb_info.ptr[(y0 + yy) * (fb_info.pitch / 4) + x0];
                uint8_t bits = glyph[yy];
                for (int xx = 0; xx < 8; ++xx) {
                    row[xx] = (bits & (0x80 >> xx)) ? color : 0xC00000u;
                }
            }
        };
        const char* prefix = "OOM HALT ";
        int x = 8;
        int y = bar_y0 + 8;
        for (int i = 0; prefix[i]; ++i) { put_glyph(prefix[i], x, y, 0xFFFFFFu); x += 8; }
        for (int i = 0; i < n;       ++i) { put_glyph(buf[i],    x, y, 0xFFFFFFu); x += 8; }
    }

    asm volatile("cli");
    for(;;) asm volatile("hlt");
}

// Bump-pool fallback, implemented in bochs_cstubs.c. The Bochs ctors do
// large allocations (icache.o's pageWriteStampTable ctor needs 4 MiB)
// through the global operator new; when the kernel's FreeListAllocator
// is exhausted we fall back to the dedicated 48 MiB Bochs pool instead
// of halting. bochs_pool_owns() lets operator delete recognise a pointer
// that came from that pool (the bump allocator does not free per-object).
extern "C" void* bochs_pool_alloc(size_t n);
extern "C" int   bochs_pool_owns(const void* p);

void* operator new(size_t size) {
    void* p = g_allocator.allocate(size);
    if (!p) p = bochs_pool_alloc(size);   // fall back to the Bochs pool
    if (!p) oom_halt(size);               // both exhausted — now halt
    return p;
}

void* operator new[](size_t size) {
    return operator new(size);
}

void operator delete(void* ptr) noexcept {
    if (!ptr) return;
    if (bochs_pool_owns(ptr)) return;     // bump-pool memory: never freed
    g_allocator.deallocate(ptr);
}

void operator delete[](void* ptr) noexcept {
    operator delete(ptr);
}

void operator delete(void* ptr, size_t size) noexcept {
    (void)size;
    operator delete(ptr);
}

void operator delete[](void* ptr, size_t size) noexcept {
    (void)size;
    operator delete[](ptr);
}


// ── Non-halting allocation for callers that must be able to fail cleanly ──
// kernel_alloc_nofail()/kernel_free() are the same FreeListAllocator +
// Bochs-pool fallback as operator new/delete above, EXCEPT they return
// nullptr on exhaustion instead of calling oom_halt(). Anything driven by
// untrusted/arbitrary user input — most notably the in-kernel TCC compiler
// in tcc_kernel.cpp, where a malformed or oversized source file can cause
// runaway allocation — must use this instead of plain `new`, otherwise a
// single bad `cc <file.c>` permanently freezes the entire OS rather than
// just failing that one command.
extern "C" void* kernel_alloc_nofail(size_t size) {
    void* p = g_allocator.allocate(size);
    if (!p) p = bochs_pool_alloc(size);
    return p;   // may be nullptr — caller must check
}

extern "C" void kernel_free(void* ptr) {
    if (!ptr) return;
    if (bochs_pool_owns(ptr)) return;
    g_allocator.deallocate(ptr);
}

// Returns the number of bytes actually usable at `ptr` (i.e. safe to read
// or write), or 0 if unknown (e.g. pointer came from the Bochs bump pool,
// which keeps no per-allocation size). The FreeListAllocator stores the
// rounded-up block size (including its own header) immediately before the
// pointer it returned, so we can recover a safe upper bound here without
// any extra bookkeeping. Used by tcc_kernel.cpp's realloc() so growing a
// buffer never reads past the end of the smaller, original allocation —
// that out-of-bounds read previously corrupted adjacent heap memory on
// every realloc-to-grow call.
extern "C" size_t kernel_alloc_usable_size(void* ptr) {
    if (!ptr) return 0;
    if (bochs_pool_owns(ptr)) return 0;   // bump pool: no recoverable size
    size_t block_size = *(size_t*)((char*)ptr - sizeof(size_t));
    if (block_size <= sizeof(size_t)) return 0;  // corrupt/garbage guard
    return block_size - sizeof(size_t);
}

// ── Non-halting byte-buffer alloc/free for ELF process images ─────────────
// load_and_execute_elf() previously allocated the guest image slab and its
// stack with plain `new uint8_t[...]`, which goes through operator new and
// therefore HALTS THE ENTIRE KERNEL on exhaustion (oom_halt()) — exactly
// like the in-kernel TCC compiler did before it was switched to
// kernel_alloc_nofail. A user launching an ELF when the heap happens to be
// tight (e.g. several Bochs slots already running, or a large compiled
// program) should see "cc: out of memory" / a failed launch, not freeze
// the whole OS over one `cc foo.c && foo`.
//
// These wrap kernel_alloc_nofail/kernel_free in a uint8_t* interface so
// load_and_execute_elf can swap its `new[]`/`delete[]` calls 1:1 without
// touching the unrelated `new[]`/`delete[]` call sites used for filesystem
// I/O buffers elsewhere in this file (those are kernel-internal and not
// driven by arbitrary user input in the same way).
extern "C" uint8_t* elf_alloc_bytes(size_t size) {
    return (uint8_t*)kernel_alloc_nofail(size);
}
extern "C" void elf_free_bytes(uint8_t* ptr) {
    kernel_free(ptr);
}
