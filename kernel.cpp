/*
 * OPTIMIZED KERNEL WITH GRAPHICS STATE MANAGEMENT
 * ================================================
 * All graphics rendering uses atomic frame composition
 * Unified color palette prevents inconsistencies
 * State machine ensures complete frames with no trailing
 */

#include <cstdarg>
#include <cstdint>
// =============================================================================
// SECTION 1: TYPE DEFS, STDLIB/CXX STUBS, AND LOW-LEVEL FUNCTIONS
// =============================================================================
#define SECTOR_SIZE 512

// --- Type Definitions ---
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef unsigned int uintptr_t;
typedef unsigned int size_t;
typedef signed long long int64_t;
// --- CXX ABI Stubs ---
namespace __cxxabiv1 {
    extern "C" int __cxa_guard_acquire(long long *g) { return !*(char *)(g); }
    extern "C" void __cxa_guard_release(long long *g) { *(char *)g = 1;}
    extern "C" void __cxa_pure_virtual() {}
    extern "C" void __cxa_throw_bad_array_new_length() {
        asm volatile("cli; hlt");
    }
    class __class_type_info { virtual void dummy(); };
    void __class_type_info::dummy() {}
    class __si_class_type_info { virtual void dummy(); };
    void __si_class_type_info::dummy() {}
}
extern "C" {
    void* memcpy(void* dest, const void* src, size_t n) { 
        uint8_t* d = (uint8_t*)dest; 
        const uint8_t* s = (const uint8_t*)src; 
        for (size_t i = 0; i < n; i++) d[i] = s[i]; 
        return dest; 
    }

    void* memset(void* ptr, int value, size_t num) { 
        uint8_t* p = (uint8_t*)ptr; 
        for (size_t i = 0; i < num; i++) p[i] = (uint8_t)value; 
        return ptr; 
    }

    void* memmove(void* dest, const void* src, size_t n) {
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        if (d < s) {
            for (size_t i = 0; i < n; i++) d[i] = s[i];
        } else {
            for (size_t i = n; i != 0; i--) d[i-1] = s[i-1];
        }
        return dest;
    }
}
// --- Forward Declarations ---
class Window;
class TerminalWindow;
class FileExplorerWindow; // New
extern "C" void kernel_main(uint32_t magic, uint32_t multiboot_addr);
void launch_new_terminal();
void launch_new_explorer(); // New
void launch_terminal_with_command(const char* command); // ADD THIS LINE

int fat32_write_file(const char* filename, const void* data, uint32_t size);
int fat32_remove_file(const char* filename);
char* fat32_read_file_as_string(const char* filename);
void fat32_list_files();
typedef struct { char name[11]; uint8_t attr; uint8_t ntres; uint8_t crt_time_tenth; uint16_t crt_time, crt_date, lst_acc_date, fst_clus_hi; uint16_t wrt_time, wrt_date, fst_clus_lo; uint32_t file_size; } __attribute__((packed)) fat_dir_entry_t;
int fat32_list_directory(const char* path, fat_dir_entry_t* buffer, int max_entries);
int fat32_find_entry(const char* filename, fat_dir_entry_t* entry_out, uint32_t* sector_out, uint32_t* offset_out);
bool fat32_init();

// --- BusyBox Extraction Function ---
extern "C" uint8_t ramdisk_start;
extern "C" uint8_t ramdisk_end;
bool extract_busybox_to_filesystem() {
    uint8_t* start = &ramdisk_start;
    uint8_t* end = &ramdisk_end;
    uint32_t size = (uint32_t)(end - start);
    
    if (size == 0 || size > 10 * 1024 * 1024) { // Sanity check: max 10MB
        return false;
    }
    
    // Write the embedded BusyBox binary to the FAT32 filesystem
    int result = fat32_write_file("busybox", start, size);
    return (result == 0);
}

// --- Global Clipboard ---
static char g_clipboard_buffer[1024] = {0}; // New

// --- Low-level I/O functions ---
static inline void outb(uint16_t port, uint8_t val) { asm volatile ("outb %0, %1" : : "a"(val), "d"(port)); }
static inline void outl(uint16_t port, uint32_t val) { asm volatile ("outl %0, %1" : : "a"(val), "d"(port)); }
static inline uint8_t inb(uint16_t port) { uint8_t ret; asm volatile ("inb %1, %0" : "=a"(ret) : "d"(port)); return ret; }
static inline uint32_t inl(uint16_t port) { uint32_t ret; asm volatile ("inl %1, %0" : "=a"(ret) : "d"(port)); return ret; }
static inline uint32_t pci_read_config_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)device << 11) | ((uint32_t)function << 8) | (offset & 0xFC);
    outl(0xCF8, address);
    return inl(0xCFC);
}
// =============================================================================
//  CENTRAL DEFINITIONS & FORWARD DECLARATIONS
// =============================================================================

// --- Type Definitions for FAT32 ---
// Moved here to be visible to all classes and functions
static bool    g_fs_encryption_enabled = false;
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
static uint8_t kernel_heap[1024 * 1024 * 8];
static size_t heap_ptr = 0;
void* operator new(size_t, void* p) { return p; }

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
};

static FreeListAllocator g_allocator;

void* operator new(size_t size) {
    return g_allocator.allocate(size);
}

void* operator new[](size_t size) {
    return operator new(size);
}

void operator delete(void* ptr) noexcept {
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


// =============================================================================
// SECTION 2: BOOTLOADER INFO, FONT, RTC
// =============================================================================
struct multiboot_info {
    uint32_t flags, mem_lower, mem_upper, boot_device, cmdline, mods_count, mods_addr;
    uint32_t syms[4], mmap_length, mmap_addr;
    uint32_t drives_length, drives_addr, config_table, boot_loader_name, apm_table;
    uint32_t vbe_control_info, vbe_mode_info;
    uint16_t vbe_mode, vbe_interface_seg, vbe_interface_off, vbe_interface_len;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch, framebuffer_width, framebuffer_height;
    uint8_t framebuffer_bpp, framebuffer_type, color_info[6];
} __attribute__((packed));

#include "font.h"

uint8_t rtc_read(uint8_t reg) { outb(0x70, reg); return inb(0x71); }
uint8_t bcd_to_bin(uint8_t val) { return ((val / 16) * 10) + (val & 0x0F); }
struct RTC_Time { uint8_t second, minute, hour, day, month; uint16_t year; };
RTC_Time read_rtc() {
    RTC_Time t;
    uint8_t century = 20;
    while (rtc_read(0x0A) & 0x80);
    uint8_t regB = rtc_read(0x0B);
    bool is_bcd = !(regB & 0x04);
    t.second = rtc_read(0x00); t.minute = rtc_read(0x02); t.hour = rtc_read(0x04);
    t.day = rtc_read(0x07); t.month = rtc_read(0x08); t.year = rtc_read(0x09);
    if (is_bcd) {
        t.second = bcd_to_bin(t.second); t.minute = bcd_to_bin(t.minute); t.hour = bcd_to_bin(t.hour);
        t.day = bcd_to_bin(t.day); t.month = bcd_to_bin(t.month); t.year = bcd_to_bin(t.year);
    }
    t.year += century * 100;
    return t;
}

// =============================================================================
// SECTION 3: GRAPHICS & WINDOWING SYSTEM WITH STATE MANAGEMENT
// =============================================================================

static uint32_t* backbuffer = nullptr;
struct FramebufferInfo { uint32_t* ptr; uint32_t width, height, pitch; } fb_info;

// =============================================================================
// UNIFIED COLOR PALETTE - PREVENTS COLOR INCONSISTENCIES
// =============================================================================
namespace ColorPalette {
    // Desktop colors
    constexpr uint32_t DESKTOP_TEAL      = 0x008080;
    constexpr uint32_t DESKTOP_BLUE      = 0x00004B; 
    constexpr uint32_t DESKTOP_GRAY      = 0x404040;
    
    // Taskbar colors
    constexpr uint32_t TASKBAR_GRAY      = 0x808080;
    constexpr uint32_t TASKBAR_DARK      = 0x606060;
    constexpr uint32_t TASKBAR_LIGHT     = 0xC0C0C0;
    
    // Window colors
    constexpr uint32_t WINDOW_BG         = 0x000000;
    constexpr uint32_t WINDOW_BORDER     = 0xC0C0C0;
    constexpr uint32_t TITLEBAR_ACTIVE   = 0x000080;
    constexpr uint32_t TITLEBAR_INACTIVE = 0x808080;
    constexpr uint32_t FILE_EXPLORER_BG  = 0xFFFFFF; // New
    
    // Button colors
    constexpr uint32_t BUTTON_FACE       = 0xC0C0C0;
    constexpr uint32_t BUTTON_HIGHLIGHT  = 0xFFFFFF;
    constexpr uint32_t BUTTON_SHADOW     = 0x808080;
    constexpr uint32_t BUTTON_CLOSE      = 0xFF0000;
    
    // Text colors
    constexpr uint32_t TEXT_BLACK        = 0x000000;
    constexpr uint32_t TEXT_WHITE        = 0xFFFFFF;
    constexpr uint32_t TEXT_GREEN        = 0x00FF00;
    constexpr uint32_t TEXT_GRAY         = 0x808080;
    
    // Cursor color
    constexpr uint32_t CURSOR_WHITE      = 0xFFFFFF;

    // Icon Colors
    constexpr uint32_t ICON_FILE_FILL    = 0xFFF1B5; // Light yellow
    constexpr uint32_t ICON_FILE_OUTLINE = 0x808080;
    constexpr uint32_t ICON_FOLDER_FILL  = 0xFFD3A1; // Light orange
    constexpr uint32_t ICON_SHORTCUT_ARROW = 0x0000FF; // Blue
}

// =============================================================================
// ENHANCED RENDER STATE MACHINE - ELIMINATES TRAILING AND ENSURES CONTINUITY
// =============================================================================

struct RenderState {
    // Frame state tracking
    uint32_t frameNumber;
    bool frameComplete;
    bool backgroundCleared;
    
    // Window rendering state
    int currentWindow;
    int renderPhase;
    
    // Progressive rendering within window
    int currentLine;
    int currentChar;
    int currentScanline;
    
    // Dirty tracking
    bool needsFullRedraw;
    bool windowsDirty;
    
    // Timing
    uint32_t lastFrameTick;
    uint32_t lastInputTick;
};

struct InputState {
    int byteIndex;
    uint8_t pendingBytes[16];
    int pendingCount;
    bool hasNewInput;
};

static RenderState g_render_state = {0, false, false, 0, 0, 0, 0, 0, true, true, 0, 0};
static InputState g_input_state = {0, {0}, 0, false};

// =============================================================================
// ENHANCED GRAPHICS DRIVER
// =============================================================================

inline int gfx_abs(int x) { return x < 0 ? -x : x; }

struct Color {
    uint8_t r, g, b, a;

    uint32_t to_rgb() const {
        return (a << 24) | (r << 16) | (g << 8) | b;
    }

    uint32_t to_bgr() const {
        return (a << 24) | (b << 16) | (g << 8) | r;
    }
};

namespace Colors {
    constexpr Color Black = {0, 0, 0, 255};
    constexpr Color White = {255, 255, 255, 255};
    constexpr Color Red = {255, 0, 0, 255};
    constexpr Color Green = {0, 255, 0, 255};
    constexpr Color Blue = {0, 0, 255, 255};
}

class GraphicsDriver;

class GraphicsDriver {
private:
    bool is_bgr_format;

    inline uint32_t convert_color(const Color& color) const {
        return is_bgr_format ? color.to_bgr() : color.to_rgb();
    }

    // This function converts a standard 0xRRGGBB color into 0xBBGGRR for BGR framebuffers
    inline uint32_t rgb_to_bgr(uint32_t color) const {
        if (!is_bgr_format) return color;

        uint8_t a = (color >> 24) & 0xFF;
        uint8_t r = (color >> 16) & 0xFF;
        uint8_t g = (color >> 8)  & 0xFF;
        uint8_t b = (color >> 0)  & 0xFF;

        return (a << 24) | (b << 16) | (g << 8) | r;
    }

public:
    GraphicsDriver() : is_bgr_format(true) {}

    void init(bool bgr_format = true) {
        is_bgr_format = bgr_format;
    }

    void clear_screen(uint32_t rgb_color) {
        if (!backbuffer || !fb_info.ptr) return;

        uint32_t color = rgb_to_bgr(rgb_color);
        uint32_t pixel_count = fb_info.width * fb_info.height;

        #ifdef __i386__
        uint32_t* target = backbuffer;
        asm volatile(
            "rep stosl"
            : "=D"(target), "=c"(pixel_count)
            : "D"(target), "c"(pixel_count), "a"(color)
            : "memory"
        );
        #else
        for (uint32_t i = 0; i < pixel_count; i++) {
            backbuffer[i] = color;
        }
        #endif
    }

    void clear_screen(const Color& color) {
        clear_screen(convert_color(color));
    }

    void put_pixel(int x, int y, uint32_t rgb_color) {
        if (backbuffer && x >= 0 && x < (int)fb_info.width && y >= 0 && y < (int)fb_info.height) {
            backbuffer[y * fb_info.width + x] = rgb_to_bgr(rgb_color);
        }
    }

    void put_pixel(int x, int y, const Color& color) {
        put_pixel(x, y, convert_color(color));
    }

    void draw_line(int x0, int y0, int x1, int y1, const Color& color) {
        int dx = gfx_abs(x1 - x0);
        int dy = gfx_abs(y1 - y0);
        int sx = x0 < x1 ? 1 : -1;
        int sy = y0 < y1 ? 1 : -1;
        int err = dx - dy;

        while (true) {
            put_pixel(x0, y0, color);

            if (x0 == x1 && y0 == y1) break;

            int e2 = 2 * err;
            if (e2 > -dy) {
                err -= dy;
                x0 += sx;
            }
            if (e2 < dx) {
                err += dx;
                y0 += sy;
            }
        }
    }

    void draw_rect(int x, int y, int w, int h, const Color& color) {
        for (int i = 0; i < w; i++) {
            put_pixel(x + i, y, color);
            put_pixel(x + i, y + h - 1, color);
        }
        for (int i = 0; i < h; i++) {
            put_pixel(x, y + i, color);
            put_pixel(x + w - 1, y + i, color);
        }
    }

    void fill_rect(int x, int y, int w, int h, const Color& color) {
        uint32_t col = convert_color(color);
        for (int dy = 0; dy < h; dy++) {
            for (int dx = 0; dx < w; dx++) {
                put_pixel(x + dx, y + dy, col);
            }
        }
    }
};

static GraphicsDriver g_gfx;

void put_pixel_back(int x, int y, uint32_t color) {
    if (backbuffer && x >= 0 && x < (int)fb_info.width && y >= 0 && y < (int)fb_info.height) {
        backbuffer[y * fb_info.width + x] = color;
    }
}

void draw_char(char c, int x, int y, uint32_t color) {
    if ((unsigned char)c > 127) return;
    const uint8_t* glyph = font + (int)c * 8;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            if ((glyph[i] & (0x80 >> j))) {
                put_pixel_back(x + j, y + i, color);
            }
        }
    }
}

void draw_string(const char* str, int x, int y, uint32_t color) {
    for (int i = 0; str[i]; i++) {
        draw_char(str[i], x + i * 8, y, color);
    }
}

// =============================================================================
// OPTIMIZED FILL RECT - ATOMIC SCANLINE RENDERING
// =============================================================================
void draw_rect_filled(int x, int y, int w, int h, uint32_t color) {
    // Clip to screen bounds
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x >= (int)fb_info.width || y >= (int)fb_info.height) return;
    if (x + w > (int)fb_info.width) w = fb_info.width - x;
    if (y + h > (int)fb_info.height) h = fb_info.height - y;
    if (w <= 0 || h <= 0) return;

    // Render entire rect atomically (no state machine - prevents tearing)
    for (int dy = 0; dy < h; dy++) {
        int screenY = y + dy;
        if (screenY >= 0 && screenY < (int)fb_info.height) {
            uint32_t* row = &backbuffer[screenY * fb_info.width + x];
            
            // Fast fill with rep stosl on x86
            #ifdef __i386__
            uint32_t count = w;
            asm volatile(
                "rep stosl"
                : "=D"(row), "=c"(count)
                : "D"(row), "c"(count), "a"(color)
                : "memory"
            );
            #else
            for (int i = 0; i < w; i++) {
                row[i] = color;
            }
            #endif
        }
    }
}
#define FAT_ATTR_DIRECTORY 0x10
// =============================================================================
// PS/2 AND INPUT SYSTEM (Abbreviated - full implementation as before)
// =============================================================================

struct PS2State {
    uint32_t lastInputCheckTick;
    uint32_t lastOutputCheckTick;
    uint8_t inputAttemptCount;
    uint8_t outputAttemptCount;
};
static PS2State g_ps2state = {0, 0, 0, 0};

#define PS2_DATA_PORT       0x60
#define PS2_STATUS_PORT     0x64
#define PS2_COMMAND_PORT    0x64
#define PS2_CMD_READ_CONFIG     0x20
#define PS2_CMD_WRITE_CONFIG    0x60
#define PS2_CMD_DISABLE_PORT1   0xAD
#define PS2_CMD_ENABLE_PORT1    0xAE
#define PS2_CMD_DISABLE_PORT2   0xA7
#define PS2_CMD_ENABLE_PORT2    0xA8
#define PS2_CMD_TEST_PORT2      0xA9
#define PS2_CMD_TEST_CTRL       0xAA
#define PS2_CMD_WRITE_PORT2     0xD4
#define MOUSE_CMD_RESET         0xFF
#define MOUSE_CMD_RESEND        0xFE
#define MOUSE_CMD_SET_DEFAULTS  0xF6
#define MOUSE_CMD_DISABLE_DATA  0xF5
#define MOUSE_CMD_ENABLE_DATA   0xF4
#define MOUSE_CMD_SET_SAMPLE    0xF3
#define MOUSE_CMD_SET_RESOLUTION 0xE8
#define PS2_STATUS_OUTPUT_FULL  0x01
#define PS2_STATUS_INPUT_FULL   0x02
#define PS2_STATUS_AUX_DATA     0x20
#define PS2_STATUS_TIMEOUT      0x40
#define PS2_ACK                 0xFA
#define PS2_RESEND              0xFE

#define KEY_UP     -1
#define KEY_DOWN   -2
#define KEY_LEFT   -3
#define KEY_RIGHT  -4
#define KEY_DELETE -5
#define KEY_HOME   -6
#define KEY_END    -7

const char sc_ascii_nomod_map[]={0,0,'1','2','3','4','5','6','7','8','9','0','-','=','\b','\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',0,'a','s','d','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v','b','n','m',',','.','/',0,0,0,' ',0};
const char sc_ascii_shift_map[]={0,0,'!','@','#','$','%','^','&','*','(',')','_','+','\b','\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n',0,'A','S','D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V','B','N','M','<','>','?',0,0,0,' ',0};
const char sc_ascii_ctrl_map[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,'\b','\t','\x11',0,0,0,0,0,0,0,0,'\x10',0,0,'\n',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,' ',0};

bool is_shift_pressed = false;
bool is_ctrl_pressed = false;
int mouse_x = 400, mouse_y = 300;
bool mouse_left_down = false;
bool mouse_left_last_frame = false;
bool mouse_right_down = false;       // New
bool mouse_right_last_frame = false; // New
char last_key_press = 0;

struct UniversalMouseState {
    int x;
    int y;
    bool left_button;
    bool right_button;
    bool middle_button;
    uint8_t packet_cycle;
    uint8_t packet_buffer[3];
    bool synchronized;
    bool initialized;
};

static UniversalMouseState universal_mouse_state = {400, 300, false, false, false, 0, {0}, false, false};

static void process_universal_mouse_packet(uint8_t data) {
    if (!universal_mouse_state.synchronized) {
        if (data & 0x08) {
            universal_mouse_state.packet_buffer[0] = data;
            universal_mouse_state.packet_cycle = 1;
            universal_mouse_state.synchronized = true;
            return;
        } else {
            return;
        }
    }
    
    universal_mouse_state.packet_buffer[universal_mouse_state.packet_cycle] = data;
    universal_mouse_state.packet_cycle++;
    
    if (universal_mouse_state.packet_cycle >= 3) {
        universal_mouse_state.packet_cycle = 0;
        
        uint8_t flags = universal_mouse_state.packet_buffer[0];
        
        if (!(flags & 0x08)) {
            universal_mouse_state.synchronized = false;
            return;
        }
        
        universal_mouse_state.left_button = flags & 0x01;
        universal_mouse_state.right_button = flags & 0x02;
        universal_mouse_state.middle_button = flags & 0x04;
        
        int8_t dx = (int8_t)universal_mouse_state.packet_buffer[1];
        int8_t dy = (int8_t)universal_mouse_state.packet_buffer[2];
        
        if (flags & 0x40) {
            dx = (dx > 0) ? 127 : -128;
        }
        if (flags & 0x80) {
            dy = (dy > 0) ? 127 : -128;
        }
        
        const int SENSITIVITY = 2;
        int move_x = dx * SENSITIVITY;
        int move_y = dy * SENSITIVITY;
        
        universal_mouse_state.x += move_x;
        universal_mouse_state.y -= move_y;
        
        if (universal_mouse_state.x < 0) universal_mouse_state.x = 0;
        if (universal_mouse_state.y < 0) universal_mouse_state.y = 0;
        if (universal_mouse_state.x >= (int)fb_info.width) 
            universal_mouse_state.x = fb_info.width - 1;
        if (universal_mouse_state.y >= (int)fb_info.height) 
            universal_mouse_state.y = fb_info.height - 1;
        
        universal_mouse_state.synchronized = true;
    }
}

// =============================================================================
// WINDOW SYSTEM
// =============================================================================

// New: Icon drawing functions
void draw_icon_file(int x, int y, bool is_shortcut) {
    draw_rect_filled(x, y, 32, 32, ColorPalette::ICON_FILE_FILL);
    draw_rect_filled(x, y, 32, 1, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x + 31, y, 1, 32, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x, y + 31, 32, 1, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x, y, 1, 32, ColorPalette::ICON_FILE_OUTLINE);
    if(is_shortcut) {
        draw_rect_filled(x + 4, y + 22, 10, 6, ColorPalette::ICON_SHORTCUT_ARROW);
        put_pixel_back(x+8, y+20, ColorPalette::ICON_SHORTCUT_ARROW);
        put_pixel_back(x+9, y+21, ColorPalette::ICON_SHORTCUT_ARROW);
    }
}

void draw_icon_folder(int x, int y) {
    draw_rect_filled(x, y + 5, 32, 27, ColorPalette::ICON_FOLDER_FILL);
    draw_rect_filled(x, y, 14, 8, ColorPalette::ICON_FOLDER_FILL);
    draw_rect_filled(x, y + 31, 32, 1, ColorPalette::ICON_FILE_OUTLINE);
}

// New: Desktop items structure
enum IconType { ICON_FILE, ICON_DIR, ICON_SHORTCUT, ICON_APP };
struct DesktopItem {
    char name[32];
    char path[128];
    int x, y;
    IconType type;
};

class Window {
public:
    int x, y, w, h;
    const char* title;
    bool has_focus;
    bool is_closed;

    Window(int x, int y, int w, int h, const char* title)
        : x(x), y(y), w(w), h(h), title(title), has_focus(false), is_closed(false) {}
    virtual ~Window() {}
    virtual void put_char(char c) {} // ADD THIS

    virtual void draw() = 0;
    virtual void on_key_press(char c) = 0;
    virtual void on_mouse_click(int mx, int my) {} // New
	virtual void on_mouse_right_click(int mx, int my) {} // ADD THIS LINE

    virtual void update() = 0;
    virtual void console_print(const char* s) {}

    bool is_in_titlebar(int mx, int my) { return mx > x && mx < x + w && my > y && my < y + 25; }
    bool is_in_close_button(int mx, int my) { int btn_x = x + w - 22, btn_y = y + 4; return mx >= btn_x && mx < btn_x + 18 && my >= btn_y && my < btn_y + 18; }
    void close() { is_closed = true; }
};

class WindowManager {
private:
    Window* windows[16];
    int num_windows;
    int focused_idx;
    int dragging_idx;
    int drag_offset_x, drag_offset_y;

    // New: Desktop & Context Menu management
    DesktopItem desktop_items[64];
    int num_desktop_items;
    int dragging_icon_idx;

    bool context_menu_active;
    int context_menu_x, context_menu_y;
	const char* context_menu_items[8];
    int num_context_menu_items;
    enum ContextType { CTX_DESKTOP, CTX_ICON, CTX_EXPLORER_ITEM }; // ADD CTX_EXPLORER_ITEM
    ContextType current_context;
    int context_icon_idx;
    char context_file_path[128]; // ADD THIS to store the file path    int num_context_menu_items;
    

public:
    WindowManager() : num_windows(0), focused_idx(-1), dragging_idx(-1), 
                      num_desktop_items(0), dragging_icon_idx(-1), 
                      context_menu_active(false) {}
    void show_file_context_menu(int mx, int my, const char* filename) {
		context_menu_active = true;
		context_menu_x = mx;
		context_menu_y = my;
		current_context = CTX_EXPLORER_ITEM;
		strncpy(context_file_path, filename, 127); // Store the filename for the action
		num_context_menu_items = 0;
		
		if (strstr(filename, ".obj") != nullptr || strstr(filename, ".OBJ") != nullptr) {
			context_menu_items[num_context_menu_items++] = "Run";
		}
		context_menu_items[num_context_menu_items++] = "Edit"; // ADDED THIS LINE
		context_menu_items[num_context_menu_items++] = "Create Shortcut";
		context_menu_items[num_context_menu_items++] = "Copy";
		context_menu_items[num_context_menu_items++] = "Delete";
	}
    // New: Load desktop items from filesystem
    // In WindowManager class
	 void print_to_window(int idx, const char* s) {
        if (idx >= 0 && idx < num_windows) {
            windows[idx]->console_print(s);
        }
    }
	 void put_char_to_focused(char c) {
        if (focused_idx >= 0 && focused_idx < num_windows) {
            windows[focused_idx]->put_char(c);
        }
    }
void load_desktop_items() {
    num_desktop_items = 0;

    // Load items from the root directory
    static fat_dir_entry_t file_list[64]; // Max 64 files on desktop
    int num_files = fat32_list_directory("/", file_list, 64);

    for (int i = 0; i < num_files && num_desktop_items < 64; ++i) {
        fat32_get_fne_from_entry(&file_list[i], desktop_items[num_desktop_items].name);
        strcpy(desktop_items[num_desktop_items].path, desktop_items[num_desktop_items].name);
        
        desktop_items[num_desktop_items].x = 30 + (num_desktop_items % 10) * 70;
        desktop_items[num_desktop_items].y = 30 + (num_desktop_items / 10) * 80;
        
        if (file_list[i].attr & FAT_ATTR_DIRECTORY) {
            desktop_items[num_desktop_items].type = ICON_DIR;
        } else {
            desktop_items[num_desktop_items].type = ICON_FILE;
        }
        num_desktop_items++;
    }
}

    void add_window(Window* win) {
        if (num_windows < 16) {
            if (focused_idx != -1 && focused_idx < num_windows) windows[focused_idx]->has_focus = false;
            windows[num_windows] = win;
            focused_idx = num_windows;
            windows[num_windows]->has_focus = true;
            num_windows++;
        }
    }

    void set_focus(int idx) {
        if (idx < 0 || idx >= num_windows || idx == focused_idx) return;
        if (focused_idx != -1 && focused_idx < num_windows) windows[focused_idx]->has_focus = false;
        Window* focused = windows[idx];
        for (int i = idx; i < num_windows - 1; i++) windows[i] = windows[i+1];
        windows[num_windows - 1] = focused;
        focused_idx = num_windows - 1;
        windows[num_windows - 1]->has_focus = true;
    }

    int get_num_windows() const { return num_windows; }
    int get_focused_idx() const { return focused_idx; }
    Window* get_window(int idx) { 
        if (idx >= 0 && idx < num_windows) return windows[idx];
        return nullptr;
    }

    void cleanup_closed_windows() {
        if (num_windows == 0) return;
        int current_idx = 0;
        while (current_idx < num_windows) {
            if (windows[current_idx]->is_closed) {
                delete windows[current_idx];
                for (int j = current_idx; j < num_windows - 1; j++) {
                    windows[j] = windows[j + 1];
                }
                num_windows--;
            } else {
                current_idx++;
            }
        }
        
        if (num_windows > 0) {
            focused_idx = num_windows - 1;
            for(int i = 0; i < num_windows; i++) windows[i]->has_focus = false;
            windows[focused_idx]->has_focus = true;
        } else {
            focused_idx = -1;
        }
    }

    void draw_desktop() {
        using namespace ColorPalette;
        
        // Taskbar base
        draw_rect_filled(0, fb_info.height - 40, fb_info.width, 40, TASKBAR_GRAY);
        
        // Terminal button with 3D effect
        int btn_x = 4, btn_y = fb_info.height - 36;
        int btn_w = 77, btn_h = 32;
        
        draw_rect_filled(btn_x, btn_y, btn_w, 1, BUTTON_HIGHLIGHT);
        draw_rect_filled(btn_x, btn_y, 1, btn_h, BUTTON_HIGHLIGHT);
        draw_rect_filled(btn_x + 1, btn_y + btn_h - 1, btn_w - 1, 1, BUTTON_SHADOW);
        draw_rect_filled(btn_x + btn_w - 1, btn_y + 1, 1, btn_h - 1, BUTTON_SHADOW);
        draw_rect_filled(btn_x + 1, btn_y + 1, btn_w - 2, btn_h - 2, BUTTON_FACE);
        draw_string("Terminal", btn_x + 10, btn_y + 12, TEXT_BLACK);

        // Draw desktop icons
        for (int i = 0; i < num_desktop_items; ++i) {
            bool is_shortcut = strstr(desktop_items[i].name, ".lnk") != nullptr;
            if (desktop_items[i].type == ICON_APP) {
                draw_icon_folder(desktop_items[i].x, desktop_items[i].y);
            } else {
                draw_icon_file(desktop_items[i].x, desktop_items[i].y, is_shortcut);
            }
            draw_string(desktop_items[i].name, desktop_items[i].x, desktop_items[i].y + 35, TEXT_WHITE);
        }
    }

    void execute_context_menu_action(int item_index); // New

    // =============================================================================
    // STATE-BASED WINDOW MANAGER UPDATE - ATOMIC FRAME RENDERING
    // =============================================================================
    void update_all() {
        // Phase 0: Begin new frame
        if (g_render_state.renderPhase == 0) {
            g_render_state.frameComplete = false;
            g_render_state.backgroundCleared = false;
            g_render_state.currentWindow = 0;
            g_render_state.renderPhase = 1;
        }
        
        // Phase 1: Clear background (done once per frame in main loop)
        if (g_render_state.renderPhase == 1) {
            g_render_state.backgroundCleared = true;
            g_render_state.renderPhase = 2;
        }
        
        // Phase 2: Draw desktop and icons
        if (g_render_state.renderPhase == 2) {
            draw_desktop();
            g_render_state.renderPhase = 3;
        }
        
        // Phase 3: Draw windows (all at once to prevent tearing)
        if (g_render_state.renderPhase == 3) {
            for (int i = 0; i < num_windows; i++) {
                if (windows[i] && !windows[i]->is_closed) {
                    windows[i]->draw();
                }
            }
            g_render_state.renderPhase = 4;
        }

        // New Phase 3.5: Draw context menu on top of everything
        if (context_menu_active) {
            int menu_width = 150;
            int item_height = 20;
            int menu_height = num_context_menu_items * item_height;
            draw_rect_filled(context_menu_x, context_menu_y, menu_width, menu_height, ColorPalette::BUTTON_FACE);
            draw_rect_filled(context_menu_x, context_menu_y, menu_width, 1, ColorPalette::BUTTON_HIGHLIGHT);
            draw_rect_filled(context_menu_x, context_menu_y, 1, menu_height, ColorPalette::BUTTON_HIGHLIGHT);
            draw_rect_filled(context_menu_x+menu_width-1, context_menu_y, 1, menu_height, ColorPalette::BUTTON_SHADOW);
            draw_rect_filled(context_menu_x, context_menu_y+menu_height-1, menu_width, 1, ColorPalette::BUTTON_SHADOW);

            for (int i = 0; i < num_context_menu_items; ++i) {
                draw_string(context_menu_items[i], context_menu_x + 5, context_menu_y + 5 + i * item_height, ColorPalette::TEXT_BLACK);
            }
        }
        
        // Phase 4: Update logic
        if (g_render_state.renderPhase == 4) {
            for (int i = 0; i < num_windows; i++) {
                if (windows[i] && !windows[i]->is_closed) {
                    windows[i]->update();
                }
            }
            g_render_state.renderPhase = 5;
        }
        
        // Phase 5: Frame complete
        if (g_render_state.renderPhase == 5) {
            g_render_state.frameComplete = true;
            g_render_state.renderPhase = 0;
            g_render_state.frameNumber++;
        }
    }

    void handle_input(char key, int mx, int my, bool left_down, bool left_clicked, bool right_clicked); // Modified
    void print_to_focused(const char* s);
};

WindowManager wm;


// =============================================================================
// I/O WAIT AND PS/2 FUNCTIONS
// =============================================================================

static inline void io_wait_short() {
    asm volatile("outb %%al, $0x80" : : "a"(0));
}

static inline void io_delay_short() {
    for (volatile int i = 0; i < 1; i++) {
        io_wait_short();
    }
}

static inline void io_delay_medium() {
    for (volatile int i = 0; i < 5; i++) {
        io_wait_short();
    }
}

static inline void io_delay_long() {
    for (volatile int i = 0; i < 100; i++) {
        io_wait_short();
    }
}

static bool ps2_wait_input_ready(uint32_t timeout = 100000) {
    while (timeout--) {
        if (!(inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_FULL)) {
            return true;
        }
        if (timeout % 100000 == 0) io_delay_medium();
    }
    return false;
}

static bool ps2_wait_output_ready(uint32_t timeout = 100000) {
    while (timeout--) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            return true;
        }
        if (timeout % 100000 == 0) io_delay_medium();
    }
    return false;
}

static void ps2_flush_output_buffer() {
    int timeout = 10;
    while ((inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) && timeout--) {
        inb(PS2_DATA_PORT);
        io_delay_medium();
    }
}

static bool ps2_write_command(uint8_t cmd) {
    if (!ps2_wait_input_ready()) return false;
    outb(PS2_COMMAND_PORT, cmd);
    io_delay_medium();
    return true;
}

static bool ps2_write_data(uint8_t data) {
    if (!ps2_wait_input_ready()) return false;
    outb(PS2_DATA_PORT, data);
    io_delay_medium();
    return true;
}

static bool ps2_read_data(uint8_t* data) {
    if (!ps2_wait_output_ready()) return false;
    *data = inb(PS2_DATA_PORT);
    return true;
}

static bool ps2_mouse_write_command(uint8_t cmd, int max_retries = 3) {
    for (int retry = 0; retry < max_retries; retry++) {
        if (!ps2_write_command(PS2_CMD_WRITE_PORT2)) continue;
        if (!ps2_write_data(cmd)) continue;
        
        uint8_t response;
        if (ps2_read_data(&response)) {
            if (response == PS2_ACK) {
                return true;
            } else if (response == PS2_RESEND) {
                io_delay_long();
                continue;
            }
        }
        io_delay_long();
    }
    return false;
}

static bool ps2_mouse_write_with_arg(uint8_t cmd, uint8_t arg) {
    if (!ps2_mouse_write_command(cmd)) return false;
    io_delay_medium();
    return ps2_mouse_write_command(arg);
}

static bool init_ps2_mouse_legacy() {
    outb(0x64, 0xA8);
    io_delay_long();
    
    outb(0x64, 0x20);
    uint8_t status = inb(0x60) | 2;
    status &= ~0x20;
    
    outb(0x64, 0x60);
    outb(0x60, status);
    io_delay_long();
    
    outb(0x64, 0xD4);
    outb(0x60, 0xF6);
    inb(0x60);
    io_delay_long();
    
    outb(0x64, 0xD4);
    outb(0x60, 0xF4);
    inb(0x60);
    io_delay_long();
    
    ps2_flush_output_buffer();
    return true;
}

static inline void pci_write_config_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)device << 11) | ((uint32_t)function << 8) | (offset & 0xFC);
    outl(0xCF8, address);
    outl(0xCFC, value);
}

struct USBLegacyInfo {
    bool has_uhci;
    bool has_ehci;
    bool has_xhci;
    uint64_t legacy_base;
    bool ps2_emulation_active;
    uint16_t pci_bus;
    uint8_t pci_device;
    uint8_t pci_function;
};

static USBLegacyInfo usb_info = {false, false, false, 0, false, 0, 0, 0};

static bool detect_usb_controllers() {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            uint32_t class_code = pci_read_config_dword(bus, device, 0, 0x08);
            uint8_t base_class = (class_code >> 24) & 0xFF;
            uint8_t sub_class = (class_code >> 16) & 0xFF;
            uint8_t prog_if = (class_code >> 8) & 0xFF;
            
            if (base_class == 0x0C && sub_class == 0x03) {
                if (prog_if == 0x20) usb_info.has_ehci = true;
                else if (prog_if == 0x30) usb_info.has_xhci = true;
                
                usb_info.pci_bus = bus;
                usb_info.pci_device = device;
                usb_info.pci_function = 0;
                
                uint32_t bar0 = pci_read_config_dword(bus, device, 0, 0x10);
                usb_info.legacy_base = bar0 & 0xFFFFFFF0;
                return true;
            }
        }
    }
    return false;
}

static bool enable_usb_legacy_support() {
    if (usb_info.has_ehci) {
        uint32_t hccparams = pci_read_config_dword(
            usb_info.pci_bus, 
            usb_info.pci_device, 
            usb_info.pci_function, 
            0x08
        );
        
        uint8_t eecp = (hccparams >> 8) & 0xFF;
        
        if (eecp >= 0x40) {
            uint32_t legsup = pci_read_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp
            );
            
            legsup |= (1 << 24);
            pci_write_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp, 
                legsup
            );
            
            for (int i = 0; i < 100; i++) {
                io_delay_long();
                legsup = pci_read_config_dword(
                    usb_info.pci_bus, 
                    usb_info.pci_device, 
                    usb_info.pci_function, 
                    eecp
                );
                if (!(legsup & (1 << 16))) break;
            }
            
            uint32_t usblegctlsts = pci_read_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp + 4
            );
            usblegctlsts &= 0xFFFF0000;
            pci_write_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp + 4, 
                usblegctlsts
            );
            
            return true;
        }
    }
    return false;
}

static bool init_ps2_mouse_hardware() {
    uint8_t data;
    
    if (usb_info.ps2_emulation_active) {
        io_delay_long();
    }
    
    ps2_write_command(PS2_CMD_DISABLE_PORT1);
    io_delay_long();
    ps2_write_command(PS2_CMD_DISABLE_PORT2);
    io_delay_long();
    
    for (int i = 0; i < 16; i++) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            inb(PS2_DATA_PORT);
        }
        io_delay_medium();
    }
    
    if (!ps2_write_command(PS2_CMD_TEST_CTRL)) return false;
    io_delay_long();
    
    bool self_test_passed = false;
    for (int retry = 0; retry < 5; retry++) {
        if (ps2_read_data(&data)) {
            if (data == 0x55) {
                self_test_passed = true;
                break;
            }
        }
        io_delay_long();
    }
    
    if (!self_test_passed) {
        return false;
    }
    
    if (!ps2_write_command(PS2_CMD_READ_CONFIG)) return false;
    if (!ps2_read_data(&data)) return false;
    
    uint8_t config = data;
    config |= 0x03;
    config &= ~0x30;
    
    if (!ps2_write_command(PS2_CMD_WRITE_CONFIG)) return false;
    if (!ps2_write_data(config)) return false;
    io_delay_long();
    
    if (!ps2_write_command(PS2_CMD_TEST_PORT2)) return false;
    io_delay_long();
    
    bool port_test_passed = false;
    if (ps2_read_data(&data)) {
        if (data == 0x00) {
            port_test_passed = true;
        }
    }
    
    if (!port_test_passed) {
        return false;
    }
    
    if (!ps2_write_command(PS2_CMD_ENABLE_PORT2)) return false;
    io_delay_long();
    
    if (!ps2_mouse_write_command(MOUSE_CMD_RESET)) return false;
    
    uint32_t bat_timeout = 10000;
    bool bat_complete = false;
    
    while (bat_timeout-- > 0) {
        if (ps2_read_data(&data)) {
            if (data == 0xAA) {
                bat_complete = true;
                io_delay_medium();
                ps2_read_data(&data);
                break;
            } else if (data == 0xFC) {
                io_delay_long();
                ps2_mouse_write_command(MOUSE_CMD_RESET);
                bat_timeout = 5000;
            }
        }
        if (bat_timeout % 100 == 0) {
            io_delay_medium();
        }
    }
    
    if (!bat_complete) {
        return false;
    }
    
    io_delay_long();
    
    if (!ps2_mouse_write_command(MOUSE_CMD_SET_DEFAULTS)) return false;
    io_delay_long();
    
    if (!ps2_mouse_write_with_arg(MOUSE_CMD_SET_SAMPLE, 100)) {
    }
    io_delay_long();
    
    if (!ps2_mouse_write_with_arg(MOUSE_CMD_SET_RESOLUTION, 3)) {
    }
    io_delay_long();
    
    outb(0x64, 0xD4);
    io_delay_medium();
    outb(0x60, 0xE6);
    io_delay_medium();
    inb(0x60);
    io_delay_medium();
    
    if (!ps2_mouse_write_command(MOUSE_CMD_ENABLE_DATA)) return false;
    io_delay_long();
    
    ps2_write_command(PS2_CMD_ENABLE_PORT1);
    io_delay_long();
    
    for (int i = 0; i < 16; i++) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            inb(PS2_DATA_PORT);
        }
        io_delay_short();
    }
    
    return true;
}

bool initialize_universal_mouse() {
    universal_mouse_state.initialized = false;
    universal_mouse_state.synchronized = false;
    universal_mouse_state.packet_cycle = 0;
    universal_mouse_state.x = fb_info.width / 2;
    universal_mouse_state.y = fb_info.height / 2;
    
    bool has_usb = detect_usb_controllers();
    if (has_usb) {
        wm.print_to_focused("USB controllers detected...\n");
        if (enable_usb_legacy_support()) {
            wm.print_to_focused("USB Legacy PS/2 emulation enabled.\n");
        }
    }
    
    wm.print_to_focused("Initializing PS/2 mouse interface...\n");
    
    if (init_ps2_mouse_hardware()) {
        universal_mouse_state.initialized = true;
        wm.print_to_focused("PS/2 mouse initialized (hardware method).\n");
        return true;
    }
    
    wm.print_to_focused("Trying legacy PS/2 initialization...\n");
    if (init_ps2_mouse_legacy()) {
        universal_mouse_state.initialized = true;
        wm.print_to_focused("PS/2 mouse initialized (legacy method).\n");
        return true;
    }
    
    wm.print_to_focused("ERROR: Mouse initialization failed.\n");
    return false;
}
void poll_input_universal() {
    last_key_press = 0;
    // Last frame state is now handled in kernel_main loop

    for (int iterations = 0; iterations < 16; iterations++) {
        uint8_t status = inb(PS2_STATUS_PORT);
        if (!(status & PS2_STATUS_OUTPUT_FULL)) break;

        uint8_t data = inb(PS2_DATA_PORT);

        if (status & PS2_STATUS_AUX_DATA) {
            process_universal_mouse_packet(data);
        } else {
            bool is_press = !(data & 0x80);
            uint8_t scancode = data & 0x7F;

            if (scancode == 0 || scancode > 0x58) continue;

            if (scancode == 0x2A || scancode == 0x36) {
                is_shift_pressed = is_press;
            } else if (scancode == 0x1D) {
                is_ctrl_pressed = is_press;
            } else if (is_press) {
                switch(scancode) {
                    case 0x48: last_key_press = KEY_UP; break;
                    case 0x50: last_key_press = KEY_DOWN; break;
                    case 0x4B: last_key_press = KEY_LEFT; break;
                    case 0x4D: last_key_press = KEY_RIGHT; break;
                    case 0x53: last_key_press = KEY_DELETE; break;
                    case 0x47: last_key_press = KEY_HOME; break;
                    case 0x4F: last_key_press = KEY_END; break;
                    default: {
                        const char* map = is_ctrl_pressed ? sc_ascii_ctrl_map :
                                          (is_shift_pressed ? sc_ascii_shift_map : sc_ascii_nomod_map);
                        if (scancode < 128 && map[scancode] != 0) {
                            last_key_press = map[scancode];
                        }
                    }
                }
            }
        }
    }

    mouse_x = universal_mouse_state.x;
    mouse_y = universal_mouse_state.y;
    mouse_left_down = universal_mouse_state.left_button;
    mouse_right_down = universal_mouse_state.right_button; // New
}
void draw_cursor(int x, int y, uint32_t color) { 
    for(int i=0;i<12;i++) put_pixel_back(x,y+i,color); 
    for(int i=0;i<8;i++) put_pixel_back(x+i,y+i,color); 
    for(int i=0;i<4;i++) put_pixel_back(x+i,y+(11-i),color); 
}




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
static fat32_bpb_t bpb;
static uint32_t fat_start_sector, data_start_sector;
static uint32_t current_directory_cluster = 0;

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

    // Switch disk
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
    if (port_num == -1 || !ahci_base) return -1;

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

    int spin = 0;
    while (spin < 1000000) {
        if ((port->ci & (1 << slot)) == 0) break;
        spin++;
    }

    if (enc_buf) { delete[] enc_buf; enc_buf = nullptr; }
    if (spin == 1000000) return -1;
    if (port->is & (1 << 30)) return -1;

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
    // Find the AHCI controller's base address
    for (uint16_t bus = 0; bus < 256; bus++) for (uint8_t dev = 0; dev < 32; dev++) if ((pci_read_config_dword(bus, dev, 0, 0) & 0xFFFF) != 0xFFFF && (pci_read_config_dword(bus, dev, 0, 0x08) >> 16) == 0x0106) { ahci_base = pci_read_config_dword(bus, dev, 0, 0x24) & 0xFFFFFFF0; goto found; }
found:
    if (!ahci_base) return;

    cmd_list = (HBA_CMD_HEADER*)alloc_aligned(32 * sizeof(HBA_CMD_HEADER), 1024);
    cmd_table_buffer = (char*)alloc_aligned(32 * 256, 128);
    char* fis_buffer = (char*)alloc_aligned(256, 256);
    
    if (!cmd_list || !cmd_table_buffer || !fis_buffer) return;

    for(int k=0; k<32; ++k) {
        cmd_list[k].ctba = (uint64_t)(uintptr_t)(cmd_table_buffer + (k * 256));
    }

    uint32_t ports_implemented = *(volatile uint32_t*)(ahci_base + 0x0C);

    for (int i = 0; i < 32; i++) {
        if (ports_implemented & (1 << i)) {
            HBA_PORT* port = (HBA_PORT*)(ahci_base + 0x100 + (i * 0x80));

            uint8_t ipm = (port->ssts >> 8) & 0x0F;
            uint8_t det = port->ssts & 0x0F;
            if (det != 3 || ipm != 1) continue;

            stop_cmd(port);

            port->clb = (uint32_t)(uintptr_t)cmd_list;
            port->clbu = (uint32_t)(((uint64_t)(uintptr_t)cmd_list) >> 32);
            port->fb = (uint32_t)(uintptr_t)fis_buffer;
            port->fbu = (uint32_t)(((uint64_t)(uintptr_t)fis_buffer) >> 32);

            port->serr = 0xFFFFFFFF;

            start_cmd(port);

            g_ahci_port = i;
            return;
        }
    }
}bool fat32_init() {
    if (!ahci_base) return false;
    char* buffer = new char[SECTOR_SIZE];

    // Boot sector is always plaintext — read it raw regardless of crypto state
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;
    int result = read_write_sectors(g_ahci_port, 0, 1, false, buffer);
    g_fs_encryption_enabled = was_enabled;

    if (result != 0) { delete[] buffer; return false; }
    memcpy(&bpb, buffer, sizeof(bpb));
    delete[] buffer;
    if (strncmp(bpb.fil_sys_type, "FAT32", 5) != 0) {
        current_directory_cluster = 0;
        return false;
    }
    fat_start_sector = bpb.rsvd_sec_cnt;
    data_start_sector = fat_start_sector + (bpb.num_fats * bpb.fat_sz32);
    current_directory_cluster = bpb.root_clus;
    return true;
}
uint64_t cluster_to_lba(uint32_t cluster) { return data_start_sector + (cluster - 2) * bpb.sec_per_clus; }
void to_83_format(const char* filename, char* out) { memset(out, ' ', 11); int i = 0, j = 0; while (filename[i] && filename[i] != '.' && j < 8) { out[j++] = (filename[i] >= 'a' && filename[i] <= 'z') ? (filename[i]-32) : filename[i]; i++; } if(filename[i] == '.') i++; j=8; while(filename[i] && j<11) { out[j++] = (filename[i] >= 'a' && filename[i] <= 'z') ? (filename[i]-32) : filename[i]; i++; } }

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
    uint32_t sector_num = fat_start_sector + (fat_offset / SECTOR_SIZE);
    read_write_sectors(g_ahci_port, sector_num, 1, false, fat_sector);
    *(uint32_t*)(fat_sector + (fat_offset % SECTOR_SIZE)) = (*(uint32_t*)(fat_sector + (fat_offset % SECTOR_SIZE)) & 0xF0000000) | (value & 0x0FFFFFFF);
    bool success = read_write_sectors(g_ahci_port, sector_num, 1, true, fat_sector) == 0;
    delete[] fat_sector;
    return success;
}

uint32_t find_free_cluster() {
    uint32_t max_clusters = (bpb.tot_sec32 - data_start_sector) / bpb.sec_per_clus + 2;
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

uint32_t allocate_cluster_chain(uint32_t num_clusters) {
    if(num_clusters == 0) return 0;
    uint32_t first = allocate_cluster();
    if(first == 0) return 0;
    uint32_t current = first;
    for(uint32_t i = 1; i < num_clusters; i++) {
        uint32_t next = allocate_cluster();
        if(next == 0) { free_cluster_chain(first); return 0; }
        write_fat_entry(current, next);
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
    uint8_t* buffer = new uint8_t[bpb.sec_per_clus * SECTOR_SIZE];
    if (read_write_sectors(g_ahci_port, cluster_to_lba(current_directory_cluster), bpb.sec_per_clus, false, buffer) != 0) {
        wm.print_to_focused("Read error\n");
        delete[] buffer;
        return;
    }

    wm.print_to_focused("Name                           Size\n");
    char lfn_buf[256] = {0};

    for (uint32_t i = 0; i < (bpb.sec_per_clus * SECTOR_SIZE); i += sizeof(fat_dir_entry_t)) {
        fat_dir_entry_t* entry = (fat_dir_entry_t*)(buffer + i);

        if (entry->name[0] == 0x00) break;
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
    for (uint8_t s = 0; s < bpb.sec_per_clus; s++) {
        uint64_t sector_lba = cluster_to_lba(current_directory_cluster) + s;
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

    delete[] dir_buf;
    if (first_cluster > 0) free_cluster_chain(first_cluster);
    return -1; // Directory is full
}

char* fat32_read_file_as_string(const char* filename) {
    char target[11]; to_83_format(filename, target);
    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];
    for (uint8_t s = 0; s < bpb.sec_per_clus; s++) {
        if (read_write_sectors(g_ahci_port, cluster_to_lba(current_directory_cluster) + s, 1, false, dir_buf) != 0) { delete[] dir_buf; return nullptr; }
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
    delete[] dir_buf; return nullptr;
}

int fat32_find_entry(const char* filename, fat_dir_entry_t* entry_out, uint32_t* sector_out, uint32_t* offset_out) {
    char lfn_buf[256] = {0};
    uint8_t current_checksum = 0;
    
    uint8_t* dir_buf = new uint8_t[SECTOR_SIZE];
    for(uint8_t s=0; s<bpb.sec_per_clus; ++s) {
        uint32_t current_sector = cluster_to_lba(current_directory_cluster) + s;
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
    delete[] dir_buf;
    return -1;
}
int fat32_list_directory(const char* path, fat_dir_entry_t* buffer, int max_entries) {
    // This implementation ignores 'path' and lists the current directory for simplicity.
    if (!ahci_base || !current_directory_cluster || !buffer) {
        return 0;
    }

    uint8_t* dir_sector_buf = new uint8_t[bpb.sec_per_clus * SECTOR_SIZE];
    if (read_write_sectors(g_ahci_port, cluster_to_lba(current_directory_cluster), bpb.sec_per_clus, false, dir_sector_buf) != 0) {
        delete[] dir_sector_buf;
        return 0; // Read error
    }

    int count = 0;
    for (uint32_t i = 0; i < (bpb.sec_per_clus * SECTOR_SIZE); i += sizeof(fat_dir_entry_t)) {
        if (count >= max_entries) break;

        fat_dir_entry_t* entry = (fat_dir_entry_t*)(dir_sector_buf + i);

        if (entry->name[0] == 0x00) break; // End of directory
        if ((uint8_t)entry->name[0] == DELETED_ENTRY) continue; // Skip deleted entries
        if (entry->attr == ATTR_LONG_NAME || (entry->attr & ATTR_VOLUME_ID)) continue; // Skip LFN and Volume ID
        
        // This is a valid file or directory, so copy it to the output buffer
        memcpy(&buffer[count], entry, sizeof(fat_dir_entry_t));
        count++;
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

    fat32_bpb_t new_bpb;
    memset(&new_bpb, 0, sizeof(fat32_bpb_t));
    new_bpb.jmp[0] = 0xEB; new_bpb.jmp[1] = 0x58; new_bpb.jmp[2] = 0x90;
    memcpy(new_bpb.oem, "MYOS    ", 8);
    new_bpb.bytes_per_sec = 512;
    new_bpb.sec_per_clus = 8;
    new_bpb.rsvd_sec_cnt = 32;
    new_bpb.num_fats = 2;
    new_bpb.media = 0xF8;
    new_bpb.sec_per_trk = 32;
    new_bpb.num_heads = 64;
    uint32_t total_sectors = (128 * 1024 * 1024) / 512;
    new_bpb.tot_sec32 = total_sectors;
    new_bpb.fat_sz32 = (total_sectors * 2) / (new_bpb.sec_per_clus + 512) + 1;
    new_bpb.root_clus = 2;
    new_bpb.fs_info = 1;
    new_bpb.bk_boot_sec = 6;
    new_bpb.drv_num = 0x80;
    new_bpb.boot_sig = 0x29;
    new_bpb.vol_id = 0x12345678; // Example volume ID
    memcpy(new_bpb.vol_lab, "MYOS VOL   ", 11);
    memcpy(new_bpb.fil_sys_type, "FAT32   ", 8);
    
    wm.print_to_focused("Writing new boot sector...\n");
    char* boot_sector_buffer = new char[SECTOR_SIZE];
    memset(boot_sector_buffer, 0, SECTOR_SIZE);
    memcpy(boot_sector_buffer, &new_bpb, sizeof(fat32_bpb_t));
    boot_sector_buffer[510] = 0x55;
    boot_sector_buffer[511] = 0xAA;
	
	boot_sector_buffer[510] = 0x00; //dummy boot for testing
    boot_sector_buffer[511] = 0x00; //dummy boot for testing
    if (read_write_sectors(g_ahci_port, 0, 1, true, boot_sector_buffer) != 0) {
        wm.print_to_focused("Error: Failed to write new boot sector.\n");
        delete[] boot_sector_buffer;
        return;
    }
    delete[] boot_sector_buffer;

    memcpy(&bpb, &new_bpb, sizeof(fat32_bpb_t));
    fat_start_sector = bpb.rsvd_sec_cnt;
    data_start_sector = fat_start_sector + (bpb.num_fats * bpb.fat_sz32);

    uint8_t* zero_sector = new uint8_t[SECTOR_SIZE];
    memset(zero_sector, 0, SECTOR_SIZE);
    wm.print_to_focused("Clearing FATs...\n");
    for (uint32_t i = 0; i < bpb.fat_sz32; ++i) {
        read_write_sectors(g_ahci_port, fat_start_sector + i, 1, true, zero_sector); // FAT1
        read_write_sectors(g_ahci_port, fat_start_sector + bpb.fat_sz32 + i, 1, true, zero_sector); // FAT2
    }

    wm.print_to_focused("Clearing root directory...\n");
    for (uint8_t i = 0; i < bpb.sec_per_clus; ++i) {
        read_write_sectors(g_ahci_port, cluster_to_lba(bpb.root_clus) + i, 1, true, zero_sector);
    }
    delete[] zero_sector;

    wm.print_to_focused("Writing initial FAT entries...\n");
    write_fat_entry(0, 0x0FFFFFF8); // Media descriptor
    write_fat_entry(1, 0x0FFFFFFF); // Reserved, EOC
    write_fat_entry(bpb.root_clus, 0x0FFFFFFF); // Root directory cluster EOC

    wm.print_to_focused("Format complete. Re-initializing filesystem...\n");
    if (fat32_init()) {
        wm.print_to_focused("FAT32 FS re-initialized successfully.\n");
    } else {
        wm.print_to_focused("FAT32 FS re-initialization failed.\n");
    }
}
class FileExplorerWindow : public Window {
private:
    char current_path[256];
    fat_dir_entry_t file_list[128];
    int num_files;
    int scroll_offset;
    int selected_index;

public:
    FileExplorerWindow(int x, int y, const char* path) 
        : Window(x, y, 400, 300, "File Explorer"), num_files(0), scroll_offset(0), selected_index(-1) {
        strncpy(current_path, path, 255);
        current_path[255] = '\0';
        refresh_contents();
    }

    void refresh_contents() {
        num_files = fat32_list_directory(current_path, file_list, 128);
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

        // Draw file list
        int max_visible_items = (h - 35) / 10;
        for (int i = 0; i < max_visible_items; ++i) {
            int file_idx = scroll_offset + i;
            if (file_idx >= num_files) break;
            
            int item_y = y + 30 + i * 10;
            char filename[13];
            fat32_get_fne_from_entry(&file_list[file_idx], filename);

            if (file_idx == selected_index) {
                draw_rect_filled(x + 2, item_y, w - 4, 10, TITLEBAR_ACTIVE);
            }

            if (file_list[file_idx].attr & FAT_ATTR_DIRECTORY) {
                draw_icon_folder(x + 5, item_y - 2);
            } else {
                bool is_shortcut = strstr(filename, ".LNK") != nullptr;
                draw_icon_file(x + 5, item_y - 2, is_shortcut);
            }

            draw_string(filename, x + 40, item_y, TEXT_BLACK);
        }
    }

    void on_key_press(char c) override {
        // Handle keyboard navigation later
    }
void on_mouse_right_click(int mx, int my) {
        int content_y = my - (y + 30);
        if (content_y < 0) return;
        int clicked_idx = scroll_offset + (content_y / 10);

        if (clicked_idx < num_files) {
            selected_index = clicked_idx;
            char filename[13];
            fat32_get_fne_from_entry(&file_list[clicked_idx], filename);

            // Tell the window manager to show the context menu for this file
            wm.show_file_context_menu(mx, my, filename);
        }
    }
    void on_mouse_click(int mx, int my) override {
        int content_y = my - (y + 30);
        if (content_y < 0) return;
        int clicked_idx = scroll_offset + (content_y / 10);
        
        if(clicked_idx < num_files) {
            selected_index = clicked_idx;
            // Basic double-click simulation
            static int last_click_idx = -1;
            static uint32_t last_click_tick = 0;
            if(clicked_idx == last_click_idx && (g_timer_ticks - last_click_tick) < 20) {
                // Double click!
                char filename[13];
                fat32_get_fne_from_entry(&file_list[clicked_idx], filename);

                // --- ADD THIS LOGIC ---
                // Check if it's an executable object file
                if (strstr(filename, ".obj") != nullptr || strstr(filename, ".OBJ") != nullptr) {
                    char command_buffer[128];
                    snprintf(command_buffer, 128, "run %s", filename);
                    launch_terminal_with_command(command_buffer);
                }
                // --- END ADDITION ---

                // Handle opening file/dir (can be expanded for directories later)
            }
            last_click_idx = clicked_idx;
            last_click_tick = g_timer_ticks;
        }
    }

    void update() override {}
};
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
    uint32_t total_clusters = (bpb.tot_sec32 - data_start_sector) / bpb.sec_per_clus + 2;
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
    uint32_t max_clusters = (bpb.tot_sec32 - data_start_sector) / bpb.sec_per_clus + 2;
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

bool scan_directory(uint32_t cluster, ChkdskStats& stats, bool fix, int depth = 0) {
    if (depth > 20) {
        wm.print_to_focused("ERROR: Directory nesting too deep!");
        return false;
    }
    
    stats.directories_checked++;
    
    uint8_t* buffer = new uint8_t[bpb.sec_per_clus * SECTOR_SIZE];
    if (read_write_sectors(g_ahci_port, cluster_to_lba(cluster), bpb.sec_per_clus, false, buffer) != 0) {
        wm.print_to_focused("ERROR: Cannot read directory cluster");
        delete[] buffer;
        return false;
    }
    
    // Create a working copy for modifications
    uint8_t* working_buffer = nullptr;
    if (fix) {
        working_buffer = new uint8_t[bpb.sec_per_clus * SECTOR_SIZE];
        memcpy(working_buffer, buffer, bpb.sec_per_clus * SECTOR_SIZE);
    }
    
    bool modified = false;
    
    for (uint32_t i = 0; i < (bpb.sec_per_clus * SECTOR_SIZE); i += sizeof(fat_dir_entry_t)) {
        // Use working buffer if fixing, otherwise use read-only buffer
        fat_dir_entry_t* entry = (fat_dir_entry_t*)((fix ? working_buffer : buffer) + i);
        
        if (entry->name[0] == 0x00) break;
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
                    mark_cluster_used(subcluster);
                    scan_directory(subcluster, stats, fix, depth + 1);
                }
            }
        }
    }
    
    // ONLY write back if in fix mode AND something was modified
    if (fix && modified && working_buffer) {
        read_write_sectors(g_ahci_port, cluster_to_lba(cluster), bpb.sec_per_clus, true, working_buffer);
    }
    
    delete[] buffer;
    if (working_buffer) {
        delete[] working_buffer;
    }
    
    return true;
}


void find_lost_clusters(ChkdskStats& stats, bool fix) {
    wm.print_to_focused("\nScanning for lost clusters...");
    
    uint32_t max_clusters = (bpb.tot_sec32 - data_start_sector) / bpb.sec_per_clus + 2;
    
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
    
    if (bpb.tot_sec32 <= data_start_sector) {
        wm.print_to_focused("ERROR: Invalid disk geometry!");
        return;
    }
    
    stats.total_clusters = (bpb.tot_sec32 - data_start_sector) / bpb.sec_per_clus;
    
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
static char file_buffer[65536]; // 64KB file buffer


// ============================================================
// Memory Management (new/delete operators)
// ============================================================

// Simple heap allocator
static unsigned char heap[1048576]; // 1MB heap
static int heap_offset = 0;


void simple_strcpy(char* dest, const char* src) {
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';
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

// ============================================================
// Enhanced Bytecode ISA with Hardware Discovery and MMIO
// ============================================================
enum TOp : unsigned char {
    // stack/data
    T_NOP=0, T_PUSH_IMM, T_PUSH_STR, T_LOAD_LOCAL, T_STORE_LOCAL, T_POP,

    // arithmetic / unary
    T_ADD, T_SUB, T_MUL, T_DIV, T_NEG,

    // comparisons
    T_EQ, T_NE, T_LT, T_LE, T_GT, T_GE,

    // control flow
    T_JMP, T_JZ, T_JNZ, T_RET,

    // I/O and args
    T_PRINT_INT, T_PRINT_CHAR, T_PRINT_STR, T_PRINT_ENDL, T_PRINT_INT_ARRAY, T_PRINT_STRING_ARRAY,
    T_READ_INT, T_READ_CHAR, T_READ_STR,
    T_PUSH_ARGC, T_PUSH_ARGV_PTR,

    // File I/O operations
    T_READ_FILE, T_WRITE_FILE, T_APPEND_FILE,

    // Array operations
    T_ALLOC_ARRAY, T_LOAD_ARRAY, T_STORE_ARRAY, T_ARRAY_SIZE, T_ARRAY_RESIZE,

    // String operations
    T_STR_CONCAT, T_STR_LENGTH, T_STR_SUBSTR, T_INT_TO_STR, T_STR_COMPARE,
    T_STR_FIND_CHAR, T_STR_FIND_STR, T_STR_FIND_LAST_CHAR, T_STR_CONTAINS,
    T_STR_STARTS_WITH, T_STR_ENDS_WITH, T_STR_COUNT_CHAR, T_STR_REPLACE_CHAR,

    // NEW: Hardware Discovery and Memory-Mapped I/O
    T_SCAN_HARDWARE,      // () -> device_count
    T_GET_DEVICE_INFO,    // (device_index) -> device_array_handle
    T_MMIO_READ8,         // (address) -> uint8_value
    T_MMIO_READ16,        // (address) -> uint16_value
    T_MMIO_READ32,        // (address) -> uint32_value
    T_MMIO_READ64,        // (address) -> uint64_value (split into two 32-bit values)
    T_MMIO_WRITE8,        // (address, value) -> success
    T_MMIO_WRITE16,       // (address, value) -> success
    T_MMIO_WRITE32,       // (address, value) -> success
    T_MMIO_WRITE64,       // (address, low32, high32) -> success
    T_GET_HARDWARE_ARRAY, // () -> hardware_device_array_handle
    T_DISPLAY_MEMORY_MAP // () -> displays formatted memory map
};

// ============================================================
// Enhanced Program buffers with hardware support
// ============================================================
struct TProgram {
    static const int CODE_MAX = 8192;
    unsigned char code[CODE_MAX];
    int pc = 0;

    static const int LIT_MAX = 4096;
    char lit[LIT_MAX];
    int lit_top = 0;

    static const int LOC_MAX = 32;
    char  loc_name[LOC_MAX][32];
    unsigned char loc_type[LOC_MAX]; // 0=int,1=char,2=string,3=int_array,4=string_array,5=device_array
    int   loc_array_size[LOC_MAX];
    int   loc_count = 0;

    int add_local(const char* name, unsigned char t, int array_size = 0){
        for(int i=0;i<loc_count;i++){ if(simple_strcmp(loc_name[i], name)==0) return i; }
        if(loc_count>=LOC_MAX) return -1;
        simple_strcpy(loc_name[loc_count], name);
        loc_type[loc_count]=t;
        loc_array_size[loc_count] = array_size;
        return loc_count++;
    }
    int get_local(const char* name){
        for(int i=0;i<loc_count;i++){ if(simple_strcmp(loc_name[i], name)==0) return i; }
        return -1;
    }
    int get_local_type(int idx){ return (idx>=0 && idx<loc_count)? loc_type[idx] : 0; }
    int get_array_size(int idx){ return (idx>=0 && idx<loc_count)? loc_array_size[idx] : 0; }

    void emit1(unsigned char op){ if(pc<CODE_MAX) code[pc++]=op; }
    void emit4(int v){ if(pc+4<=CODE_MAX){ code[pc++]=v&0xff; code[pc++]=(v>>8)&0xff; code[pc++]=(v>>16)&0xff; code[pc++]=(v>>24)&0xff; } }
    int  mark(){ return pc; }
    void patch4(int at, int v){ if(at+4<=CODE_MAX){ code[at+0]=v&0xff; code[at+1]=(v>>8)&0xff; code[at+2]=(v>>16)&0xff; code[at+3]=(v>>24)&0xff; } }

    const char* add_lit(const char* s){
        int n = tcc_strlen(s)+1;
        if(lit_top+n > LIT_MAX) return "";
        char* p = &lit[lit_top];
        simple_memcpy(p, s, n);
        lit_top += n;
        return p;
    }
};

// ============================================================
// Enhanced Tokenizer with hardware and MMIO keywords
// ============================================================
enum TTokType { TT_EOF, TT_ID, TT_NUM, TT_STR, TT_CH, TT_KW, TT_OP, TT_PUNC };
struct TTok { TTokType t; char v[256]; int ival; };

struct TLex {
    const char* src; int pos; int line;
    void init(const char* s){ src=s; pos=0; line=1; }

    void skipws(){
        for(;;){
            char c=src[pos];
            if(c==' '||c=='\t'||c=='\r'||c=='\n'){ if(c=='\n') line++; pos++; continue; }
            if(c=='/' && src[pos+1]=='/'){ pos+=2; while(src[pos] && src[pos]!='\n') pos++; continue; }
            if(c=='/' && src[pos+1]=='*'){ pos+=2; while(src[pos] && !(src[pos]=='*'&&src[pos+1]=='/')) pos++; if(src[pos]) pos+=2; continue; }
            break;
        }
    }

    TTok number(){
        TTok t; t.t=TT_NUM; t.ival=0; int i=0;
        // Support hex numbers (0x prefix)
        if(src[pos] == '0' && (src[pos+1] == 'x' || src[pos+1] == 'X')) {
            pos += 2;
            t.v[i++] = '0'; t.v[i++] = 'x';
            while(i < 63 && ((src[pos] >= '0' && src[pos] <= '9') ||
                             (src[pos] >= 'a' && src[pos] <= 'f') ||
                             (src[pos] >= 'A' && src[pos] <= 'F'))) {
                char c = src[pos];
                t.v[i++] = c;
                if(c >= '0' && c <= '9') t.ival = t.ival * 16 + (c - '0');
                else if(c >= 'a' && c <= 'f') t.ival = t.ival * 16 + (c - 'a' + 10);
                else if(c >= 'A' && c <= 'F') t.ival = t.ival * 16 + (c - 'A' + 10);
                pos++;
            }
        } else {
            while(tcc_is_digit(src[pos])){ t.v[i++]=src[pos]; t.ival = t.ival*10 + (src[pos]-'0'); pos++; if(i>=63) break; }
        }
        t.v[i]=0; return t;
    }

    TTok ident(){
        TTok t; t.t=TT_ID; int i=0;
        while(tcc_is_alnum(src[pos])){ t.v[i++]=src[pos++]; if(i>=63) break; } t.v[i]=0;
        // Enhanced keywords with hardware and MMIO functions
        const char* kw[]={"int","char","string","return","if","else","while","break","continue",
                          "cin","cout","endl","argc","argv","read_file","write_file","append_file",
                          "array_size","array_resize","str_length","str_substr","int_to_str","str_compare",
                          "str_find_char","str_find_str","str_find_last_char","str_contains",
                          "str_starts_with","str_ends_with","str_count_char","str_replace_char",
                          "scan_hardware","get_device_info","get_hardware_array","display_memory_map",
                          "mmio_read8","mmio_read16","mmio_read32","mmio_read64",
                          "mmio_write8","mmio_write16","mmio_write32","mmio_write64",0};
        for(int k=0; kw[k]; ++k){ if(simple_strcmp(t.v,kw[k])==0){ t.t=TT_KW; break; } }
        return t;
    }

    TTok string(){
        TTok t; t.t=TT_STR; int i=0; pos++;
        while(src[pos] && src[pos]!='"'){ if(i<256) t.v[i++]=src[pos]; pos++; }
        t.v[i]=0; if(src[pos]=='"') pos++; return t;
    }

    TTok chlit(){
        TTok t; t.t=TT_CH; t.v[0]=0; int v=0; pos++; // skip '
        if(src[pos] && src[pos+1]=='\''){ v = (unsigned char)src[pos]; pos+=2; }
        t.ival = v; return t;
    }

    TTok op_or_punc(){
        TTok t; t.t=TT_OP; t.v[0]=src[pos]; t.v[1]=0; char c=src[pos];
        if(c=='<' && src[pos+1]=='<'){ t.v[0]='<'; t.v[1]='<'; t.v[2]=0; pos+=2; return t; }
        if(c=='>' && src[pos+1]=='>'){ t.v[0]='>'; t.v[1]='>'; t.v[2]=0; pos+=2; return t; }
        if((c=='='||c=='!'||c=='<'||c=='>') && src[pos+1]=='='){ t.v[0]=c; t.v[1]='='; t.v[2]=0; pos+=2; return t; }
        pos++; if(c=='('||c==')'||c=='{'||c=='}'||c==';'||c==','||c=='['||c==']') t.t=TT_PUNC; return t;
    }

    TTok next(){
        skipws();
        if(src[pos]==0){ TTok t; t.t=TT_EOF; t.v[0]=0; return t; }
        if(src[pos]=='"') return string();
        if(src[pos]=='\'') return chlit();
        if(tcc_is_digit(src[pos]) || (src[pos]=='0' && (src[pos+1]=='x'||src[pos+1]=='X'))) return number();
        if(tcc_is_alpha(src[pos])) return ident();
        return op_or_punc();
    }
};

// ============================================================
// Enhanced Parser / Compiler with Hardware and MMIO support
// ============================================================
struct TCompiler {
    TLex lx; TTok tk; TProgram pr;

    int brk_pos[32]; int brk_cnt=0;
    int cont_pos[32]; int cont_cnt=0;

    void adv(){ tk = lx.next(); }
    int  accept(const char* s){ if(simple_strcmp(tk.v,s)==0){ adv(); return 1; } return 0; }
    void expect(const char* s){ if(!accept(s)) { printf("Parse error near: %s\n", tk.v); } }

    void parse_primary(){
        if(tk.t==TT_NUM){ pr.emit1(T_PUSH_IMM); pr.emit4(tk.ival); adv(); return; }
        if(tk.t==TT_CH){ pr.emit1(T_PUSH_IMM); pr.emit4(tk.ival); adv(); return; }
        if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"argc")==0){ pr.emit1(T_PUSH_ARGC); adv(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); return; }

        // File I/O built-ins
        if(tk.t==TT_KW && simple_strcmp(tk.v,"read_file")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_READ_FILE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"write_file")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_WRITE_FILE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"append_file")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_APPEND_FILE); return;
        }

        // Array built-ins
        if(tk.t==TT_KW && simple_strcmp(tk.v,"array_size")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_ARRAY_SIZE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"array_resize")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_ARRAY_RESIZE); return;
        }

        // String built-ins
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_length")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_STR_LENGTH); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_substr")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(",");
            parse_expression(); expect(")"); pr.emit1(T_STR_SUBSTR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"int_to_str")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_INT_TO_STR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_compare")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_COMPARE); return;
        }

        // String search functions
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_find_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_FIND_CHAR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_find_str")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_FIND_STR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_find_last_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_FIND_LAST_CHAR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_contains")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_CONTAINS); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_starts_with")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_STARTS_WITH); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_ends_with")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_ENDS_WITH); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_count_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_COUNT_CHAR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_replace_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(",");
            parse_expression(); expect(")"); pr.emit1(T_STR_REPLACE_CHAR); return;
        }

        // NEW: Hardware Discovery Functions
        if(tk.t==TT_KW && simple_strcmp(tk.v,"scan_hardware")==0){
            adv(); expect("("); expect(")"); pr.emit1(T_SCAN_HARDWARE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"get_device_info")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_GET_DEVICE_INFO); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"get_hardware_array")==0){
            adv(); expect("("); expect(")"); pr.emit1(T_GET_HARDWARE_ARRAY); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"display_memory_map")==0){
            adv(); expect("("); expect(")"); pr.emit1(T_DISPLAY_MEMORY_MAP); return;
        }

        // NEW: Memory-Mapped I/O Functions
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read8")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ8); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read16")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ16); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read32")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ32); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read64")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ64); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write8")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE8); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write16")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE16); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write32")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE32); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write64")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(",");
            parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE64); return;
        }

        if(tk.t==TT_PUNC && tk.v[0]=='('){ adv(); parse_expression(); expect(")"); return; }

        if(tk.t==TT_ID){
            int idx = pr.get_local(tk.v);
            if(idx<0){ printf("Unknown var %s\n", tk.v); }
            char var_name[32]; simple_strcpy(var_name, tk.v);
            adv();

            // Array indexing
            if(tk.t==TT_PUNC && tk.v[0]=='['){
                pr.emit1(T_LOAD_LOCAL); pr.emit4(idx); // push handle
                adv(); // past '['
                parse_expression(); // push index
                expect("]");
                pr.emit1(T_LOAD_ARRAY);
                return;
            }

            pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);
            return;
        }
    }

    void parse_unary(){
        if(accept("-")){ parse_unary(); pr.emit1(T_NEG); return; }
        parse_primary();
    }

    void parse_term(){
        parse_unary();
        while(tk.v[0]=='*' || tk.v[0]=='/'){
            char op=tk.v[0]; adv(); parse_unary();
            pr.emit1(op=='*'?T_MUL:T_DIV);
        }
    }

    void parse_arith(){
        parse_term();
        while(tk.v[0]=='+' || tk.v[0]=='-'){
            char op=tk.v[0]; adv(); parse_term();
            if(op=='+') {
                pr.emit1(T_ADD); // This will be overridden for strings in VM
            } else {
                pr.emit1(T_SUB);
            }
        }
    }

    void parse_cmp(){
        parse_arith();
        while(tk.t==TT_OP && (simple_strcmp(tk.v,"==")==0 || simple_strcmp(tk.v,"!=")==0 ||
              simple_strcmp(tk.v,"<")==0 || simple_strcmp(tk.v,"<=")==0 ||
              simple_strcmp(tk.v,">")==0 || simple_strcmp(tk.v,">=")==0)){
            char opv[3]; simple_strcpy(opv, tk.v); adv(); parse_arith();
            if(simple_strcmp(opv,"==")==0) pr.emit1(T_EQ);
            else if(simple_strcmp(opv,"!=")==0) pr.emit1(T_NE);
            else if(simple_strcmp(opv,"<")==0)  pr.emit1(T_LT);
            else if(simple_strcmp(opv,"<=")==0) pr.emit1(T_LE);
            else if(simple_strcmp(opv,">")==0)  pr.emit1(T_GT);
            else pr.emit1(T_GE);
        }
    }

    void parse_expression(){ parse_cmp(); }

    void parse_decl(unsigned char tkind){
        adv(); // past type keyword
        if(tk.t!=TT_ID){ printf("Expected identifier\n"); return; }
        char nm[32]; simple_strcpy(nm, tk.v); adv();

        int array_size = 0;
        // Array declaration syntax: int arr[size] or string arr[size]
        if(tk.t==TT_PUNC && tk.v[0]=='['){
            adv();
            if(tk.t==TT_NUM){
                array_size = tk.ival;
                adv();
            } else {
                printf("Expected array size\n"); return;
            }
            expect("]");

            if (tkind == 0) tkind = 3; // int -> int_array
            else if (tkind == 2) tkind = 4; // string -> string_array
        }

        int idx = pr.add_local(nm, tkind, array_size);

        // If it's an array, allocate it now, before parsing initializer
        if (tkind == 3 || tkind == 4) {
            pr.emit1(T_PUSH_IMM); pr.emit4(array_size);
            pr.emit1(T_ALLOC_ARRAY);
            pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
        }

        if(accept("=")){
            if(tkind==3 || tkind==4){ // Array initialization
                expect("{");
                int i = 0;
                do {
                    if (tk.t == TT_PUNC && tk.v[0] == '}') break; // empty list or trailing comma
                    if (i >= array_size) {
                        printf("Too many initializers for array\n");
                        while(!accept("}")) { if(tk.t==TT_EOF) break; adv(); }
                        goto end_init;
                    }

                    pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);      // 1. Push handle
                    pr.emit1(T_PUSH_IMM); pr.emit4(i);        // 2. Push index
                    parse_expression();                       // 3. Push value
                    pr.emit1(T_STORE_ARRAY);                    // 4. Store
                    i++;
                } while(accept(","));
                expect("}");
                end_init:;
            } else if(tkind==2){ // string
                if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); }
                else if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); }
                else if(tk.t==TT_ID){ int j=pr.get_local(tk.v); adv(); pr.emit1(T_LOAD_LOCAL); pr.emit4(j); }
                else { parse_expression(); }
                pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
            } else {
                parse_expression();
                pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
            }
        }
        expect(";");
    }

    void parse_assign_or_coutcin(){
        if(tk.t==TT_KW && simple_strcmp(tk.v,"cout")==0){ adv();
            for(;;){
                expect("<<");
                if(tk.t==TT_KW && simple_strcmp(tk.v,"endl")==0){ adv(); pr.emit1(T_PRINT_ENDL); }
                else if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); pr.emit1(T_PRINT_STR); }
                else if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); pr.emit1(T_PRINT_STR); }
                else if(tk.t==TT_ID){
                    char var_name[32]; simple_strcpy(var_name, tk.v);
                    int idx = pr.get_local(tk.v); int ty = pr.get_local_type(idx); adv();

                    // Handle array element printing vs whole array printing
                    if(tk.t==TT_PUNC && tk.v[0]=='['){
                        pr.emit1(T_LOAD_LOCAL); pr.emit4(idx); // load array
                        adv(); // past '['
                        parse_expression(); // push index
                        expect("]");
                        pr.emit1(T_LOAD_ARRAY); // load element
                        if (ty == 3) pr.emit1(T_PRINT_INT);      // int array element
                        else if (ty == 4) pr.emit1(T_PRINT_STR);  // string array element
                        else if (ty == 5) pr.emit1(T_PRINT_INT);  // device array element
                    } else {
                        pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);
                        if(ty==4) pr.emit1(T_PRINT_STRING_ARRAY); // Print whole string array
                        else if(ty==3) pr.emit1(T_PRINT_INT_ARRAY); // Print whole int array
                        else if(ty==2) pr.emit1(T_PRINT_STR);
                        else if(ty==1) pr.emit1(T_PRINT_CHAR);
                        else pr.emit1(T_PRINT_INT);
                    }
                } else { parse_expression(); pr.emit1(T_PRINT_INT); }
                if(tk.t==TT_PUNC && tk.v[0]==';'){ adv(); break; }
            }
            return;
        }
        if (tk.t==TT_KW && simple_strcmp(tk.v,"cin")==0) {
			adv();
			for (;;) {
				expect(">>");
				if (tk.t != TT_ID) {
					printf("cin expects identifier\n");
					return;
				}
				int idx = pr.get_local(tk.v);
				int ty  = pr.get_local_type(idx);
				adv(); // past identifier

				// CRITICAL FIX: Emit the variable index with the READ instruction
				// so the VM knows WHERE to store the result
				if (ty == 2) {
					pr.emit1(T_READ_STR);
					pr.emit4(idx);  // Index to store into
				}
				else if (ty == 1) {
					pr.emit1(T_READ_CHAR);
					pr.emit4(idx);
				}
				else {
					pr.emit1(T_READ_INT);
					pr.emit4(idx);
				}

				// DO NOT emit T_STORE_LOCAL - the READ instruction handles storage

				if (tk.t == TT_PUNC && tk.v[0] == ';') {
					adv();
					break;
				}
			}
			return;
		}

        if(tk.t==TT_ID){
            int idx = pr.get_local(tk.v);
            if(idx<0){ printf("Unknown var %s\n", tk.v); }
            int ty = pr.get_local_type(idx);
            adv();

            // Array element assignment
            if(tk.t==TT_PUNC && tk.v[0]=='['){
                pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);  // 1. Push handle
                adv(); // past '['
                parse_expression();                      // 2. Push index
                expect("]");
                expect("=");
                parse_expression();                      // 3. Push value
                pr.emit1(T_STORE_ARRAY);                    // 4. Store
                expect(";");
                return;
            }

            expect("=");
            if(ty==2){
                if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); }
                else if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); }
                else if(tk.t==TT_ID){ int j=pr.get_local(tk.v); adv(); pr.emit1(T_LOAD_LOCAL); pr.emit4(j); }
                else { parse_expression(); }
            } else {
                parse_expression();
            }
            pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
            expect(";");
            return;
        }

        // Expression statement
        parse_expression();
        pr.emit1(T_POP); // Pop unused result
        expect(";");
    }

    void parse_if(){
        adv(); expect("("); parse_expression(); expect(")");
        pr.emit1(T_JZ); int jz_at = pr.mark(); pr.emit4(0);
        parse_block();
        int has_else = (tk.t==TT_KW && simple_strcmp(tk.v,"else")==0);
        if(has_else){
            pr.emit1(T_JMP); int j_at = pr.mark(); pr.emit4(0);
            int here = pr.pc; pr.patch4(jz_at, here);
            adv(); // else
            parse_block();
            int end = pr.pc; pr.patch4(j_at, end);
        } else {
            int here = pr.pc; pr.patch4(jz_at, here);
        }
    }

    void parse_while(){
        adv(); expect("("); int cond_ip = pr.pc; parse_expression(); expect(")");
        pr.emit1(T_JZ); int jz_at = pr.mark(); pr.emit4(0);
        int brk_base=brk_cnt, cont_base=cont_cnt;
        parse_block();
        for(int i=cont_base;i<cont_cnt;i++){ pr.patch4(cont_pos[i], cond_ip); }
        cont_cnt = cont_base;
        pr.emit1(T_JMP); pr.emit4(cond_ip);
        int end_ip = pr.pc; pr.patch4(jz_at, end_ip);
        for(int i=brk_base;i<brk_cnt;i++){ pr.patch4(brk_pos[i], end_ip); }
        brk_cnt = brk_base;
    }

    void parse_block(){
        if(accept("{")){
            while(!(tk.t==TT_PUNC && tk.v[0]=='}') && tk.t!=TT_EOF) parse_stmt();
            expect("}");
        } else {
            parse_stmt();
        }
    }

    void parse_stmt(){
        if(tk.t==TT_KW && simple_strcmp(tk.v,"int")==0){ parse_decl(0); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"char")==0){ parse_decl(1); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"string")==0){ parse_decl(2); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"return")==0){ adv(); parse_expression(); pr.emit1(T_RET); expect(";"); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"if")==0){ parse_if(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"while")==0){ parse_while(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"break")==0){ adv(); expect(";"); pr.emit1(T_JMP); int at=pr.mark(); pr.emit4(0); brk_pos[brk_cnt++]=at; return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"continue")==0){ adv(); expect(";"); pr.emit1(T_JMP); int at=pr.mark(); pr.emit4(0); cont_pos[cont_cnt++]=at; return; }
        parse_assign_or_coutcin();
    }

    int compile(const char* source){
        lx.init(source); adv();
        if(!(tk.t==TT_KW && simple_strcmp(tk.v,"int")==0)) { printf("Expected 'int' at start\n"); return -1; }
        adv();
        if(!(tk.t==TT_ID && simple_strcmp(tk.v,"main")==0)){ printf("Expected main\n"); return -1; }
        adv(); expect("("); expect(")"); parse_block();
        pr.emit1(T_PUSH_IMM); pr.emit4(0); pr.emit1(T_RET);
        return pr.pc;
    }
};

// ============================================================
// MODIFIED TinyVM FOR PARTIAL COMPUTING
// ============================================================
struct TinyVM {
    static const int STK_MAX = 1024;
    int   stk[STK_MAX]; int sp=0;
    int   locals[TProgram::LOC_MAX];
    int   argc; const char** argv;
    TProgram* P;
    char str_in[256];
    uint64_t ahci_base; int port; // for file I/O
    int bound_window_idx = -1; 
	int pending_store_idx = 0;  // Where to store READ result

    // --- EXECUTION STATE FOR PARTIAL COMPUTING ---
    int ip = 0;             // Instruction Pointer (Persistent)
    bool is_running = false; // Is a program currently active?
    int exit_code = 0;      // Store result when finished
    // ---------------------------------------------
	// --- NEW: ASYNC INPUT STATE ---
	Window* bound_window = nullptr;   // instead of int bound_window_idx
    bool waiting_for_input = false;
    int  input_mode = 0;
    char input_buffer[256];
    int  input_pos = 0;
    // String pool for dynamic string management
    static const int STRING_POOL_SIZE = 8192;
    char string_pool[STRING_POOL_SIZE];
    int string_pool_top = 0;

    // Simple array management
    struct Array {
        int* data;
        int size;
        int capacity;
    };
    static const int MAX_ARRAYS = 64;
    Array arrays[MAX_ARRAYS];
    int array_count = 0;

    // Special array handle for hardware devices
    int hardware_array_handle = 0;

    inline void push(int v){ if(sp<STK_MAX) stk[sp++]=v; }
    inline int  pop(){ return sp?stk[--sp]:0; }

    // --- Helper Methods (Same as before) ---
    uint8_t mmio_read_8(uint64_t addr) { return *(volatile uint8_t*)addr; }
    uint16_t mmio_read_16(uint64_t addr) { return *(volatile uint16_t*)addr; }
    uint32_t mmio_read_32(uint64_t addr) { return *(volatile uint32_t*)addr; }
    uint64_t mmio_read_64(uint64_t addr) { return *(volatile uint64_t*)addr; }
    bool mmio_write_8(uint64_t addr, uint8_t value) { *(volatile uint8_t*)addr = value; return true; }
    bool mmio_write_16(uint64_t addr, uint16_t value) { *(volatile uint16_t*)addr = value; return true; }
    bool mmio_write_32(uint64_t addr, uint32_t value) { *(volatile uint32_t*)addr = value; return true; }
    bool mmio_write_64(uint64_t addr, uint64_t value) { *(volatile uint64_t*)addr = value; return true; }

    // String helpers
    const char* alloc_string(int len) {
        if(string_pool_top + len + 1 > STRING_POOL_SIZE) string_pool_top = 0; 
        if(string_pool_top + len + 1 > STRING_POOL_SIZE) return nullptr;
        char* result = &string_pool[string_pool_top];
        string_pool_top += len + 1;
        return result;
    }
    // (Simplified string helpers for brevity - assuming originals exist or use minimal versions)
    // Note: Ensure your original string helper functions (concat_strings, etc.) are inside here or available.
	  
    // Array helpers
    int alloc_array(int size) {
        if(array_count >= MAX_ARRAYS) return 0;
        int handle = array_count + 1;
        arrays[array_count].data = new int[size];
        arrays[array_count].size = size;
        arrays[array_count].capacity = size;
        for(int i=0; i<size; i++) arrays[array_count].data[i] = 0;
        array_count++;
        return handle;
    }
    Array* get_array(int handle) {
        if(handle > 0 && handle <= array_count) return &arrays[handle-1];
        return nullptr;
    }
    int resize_array(int handle, int new_size) {
        Array* arr = get_array(handle);
        if(!arr) return 0;
        int* new_data = new int[new_size];
        int copy_size = (arr->size < new_size) ? arr->size : new_size;
        for(int i=0; i<copy_size; i++) new_data[i] = arr->data[i];
        for(int i=copy_size; i<new_size; i++) new_data[i] = 0;
        delete[] arr->data;
        arr->data = new_data;
        arr->size = new_size;
        arr->capacity = new_size;
        return handle;
    }
    int create_device_info_array(int index) { return 0; /* stub */ }
    int create_hardware_array() { return 0; /* stub */ }
    int scan_hardware() { return hardware_count; }

    // --- NEW: INITIALIZE EXECUTION ---
     // UPDATED start_execution
      void start_execution(TProgram& prog,
                         int ac,
                         const char** av,
                         uint64_t base,
                         int p,
                         Window* win)   // NOTE: Window* not int
    {
        bound_window = win;
        P=&prog; argc=ac; argv=av; ahci_base=base; port=p;
        sp=0; ip=0; is_running=true; exit_code=0;
        waiting_for_input = false; input_mode = 0; input_pos = 0;
        array_count = 0; hardware_array_handle = 0; string_pool_top = 0;
        for (int i=0;i<TProgram::LOC_MAX;i++) locals[i]=0;

        for(int i = 0; i < P->loc_count; i++) {
            if(P->loc_type[i] == 3 || P->loc_type[i] == 4) {
                int arr_handle = alloc_array(P->loc_array_size[i]);
                locals[i] = arr_handle;
            }
        }
    }
	
	void vm_print(const char* s) {
		if (bound_window) {
			bound_window->console_print(s);  // Route to window!
		} else {
			printf(s);  // Fallback if no window
		}
	}

	void vm_putc(char c) {
		if (bound_window) {
			// Use put_char directly, which adds to current line without wrapping
			bound_window->put_char(c);
		} else {
			printf("%c", c);  // Fallback
		}
	}

    void feed_input(char c) {
		if (!waiting_for_input) return;
		
		if (c == '\n' || c == '\r') {
			input_buffer[input_pos] = 0;
			vm_putc('\n');
			
			if (input_mode == 1) {
				locals[pending_store_idx] = simple_atoi(input_buffer);
			}
			else if (input_mode == 2) {
				locals[pending_store_idx] = (unsigned char)input_buffer[0];
			}
			else if (input_mode == 3) {
				simple_strcpy(str_in, input_buffer);
				locals[pending_store_idx] = (int)str_in;
			}
			
			waiting_for_input = false;
			input_pos = 0;
			input_mode = 0;
			pending_store_idx = 0;
			
		} else if (c == '\b') {
			if (input_pos > 0) {
				input_pos--;
				input_buffer[input_pos] = 0;
				vm_putc('\b');
			}
		} else if (c >= 32 && c <= 126 && input_pos < 255) {
			input_buffer[input_pos++] = c;
			vm_putc(c);
		}
	}



    // --- NEW: TICK FUNCTION (Runs 'steps' instructions) ---
    // Returns: 1 if still running, 0 if finished
    int tick(int steps) {
        if (!is_running) return 0;
        if (waiting_for_input) return 1; // Still running, just paused

        int steps_done = 0;
        while(steps_done < steps && ip < P->pc && is_running){
			if (waiting_for_input) break;

            TOp op = (TOp)P->code[ip++];

            // PASTE YOUR ORIGINAL HUGE SWITCH STATEMENT HERE
            // IMPORTANT MODIFICATION: Replace "return rv;" with "exit_code = rv; is_running=false; return 0;"
            switch(op){
                case T_NOP: break;
                case T_PUSH_IMM: { int v= *(int*)&P->code[ip]; ip+=4; push(v); } break;
                case T_PUSH_STR: { int p= *(int*)&P->code[ip]; ip+=4; push(p); } break;
                case T_LOAD_LOCAL:{ int i=*(int*)&P->code[ip]; ip+=4; push(locals[i]); } break;
                case T_STORE_LOCAL:{ int i=*(int*)&P->code[ip]; ip+=4; locals[i]=pop(); } break;
                case T_POP: { if(sp) --sp; } break;
                case T_ADD: { int b=pop(), a=pop(); push(a+b); } break;
                case T_SUB: { int b=pop(), a=pop(); push(a-b); } break;
                case T_MUL: { int b=pop(), a=pop(); push(a*b); } break;
                case T_DIV: { int b=pop(), a=pop(); push(b? a/b:0); } break;
                case T_NEG: { int a=pop(); push(-a); } break;
                case T_EQ: { int b=pop(), a=pop(); push(a==b); } break;
                case T_NE: { int b=pop(), a=pop(); push(a!=b); } break;
                case T_LT: { int b=pop(), a=pop(); push(a<b); } break;
                case T_GT: { int b=pop(), a=pop(); push(a>b); } break;
                case T_LE: { int b=pop(), a=pop(); push(a<=b); } break;
                case T_GE: { int b=pop(), a=pop(); push(a>=b); } break;
                case T_JMP: { int t=*(int*)&P->code[ip]; ip=t; } break;
                case T_JZ:  { int t=*(int*)&P->code[ip]; ip+=4; int v=pop(); if(v==0) ip=t; } break;
                case T_JNZ: { int t=*(int*)&P->code[ip]; ip+=4; int v=pop(); if(v!=0) ip=t; } break;
                case T_PRINT_INT: {
					int v = pop();
					char buf[16];
					int_to_string(v, buf);
					printf("%s", buf);
				} break;

				case T_PRINT_CHAR: {
					int v = pop();
					char buf[2] = { (char)(v & 0xFF), 0 };
					printf("%s", buf);
				} break;

				case T_PRINT_STR: {
					const char* p = (const char*)pop();
					if (p) printf("%s", p);
				} break;

				case T_PRINT_ENDL: {
					printf("\n");
				} break;

				case T_PRINT_INT_ARRAY: {
					int handle = pop();
					Array* arr = get_array(handle);
					if (arr) {
						for (int i = 0; i < arr->size; i++) {
							char buf[16];
							int_to_string(arr->data[i], buf);
							printf("%s", buf);
							if (i < arr->size - 1) printf(", ");
						}
					}
				} break;

				case T_PRINT_STRING_ARRAY: {
					int handle = pop();
					// Handle string array printing
				} break;

				case T_READ_INT: {
					int idx = *(int*)&P->code[ip]; ip+=4;  // READ the variable index
					waiting_for_input = true;
					input_mode = 1;
					input_pos = 0;
					pending_store_idx = idx;  // Store where to write the result
					return 1;
				} break;

				case T_READ_CHAR: {
					int idx = *(int*)&P->code[ip]; ip+=4;
					waiting_for_input = true;
					input_mode = 2;
					input_pos = 0;
					pending_store_idx = idx;
					return 1;
				} break;

				case T_READ_STR: {
					int idx = *(int*)&P->code[ip]; ip+=4;
					waiting_for_input = true;
					input_mode = 3;
					input_pos = 0;
					pending_store_idx = idx;
					return 1;
				} break;
                // CRITICAL CHANGE: RETURN HANDLING
                case T_RET: { 
                    int rv=pop(); 
                    exit_code = rv; 
                    is_running = false; 
                    return 0; // Finished
                } break;
                
                default: break;
            }
            steps_done++;
        }
        
        if (ip >= P->pc && !waiting_for_input) {
            is_running = false;
            return 0;
        }

        return 1; // Still running
    }
};
// --- GLOBAL VM STATE ---

// --- GLOBAL PROCESS TABLE ---
#define MAX_PROCESSES 4
TinyVM processes[MAX_PROCESSES];
TProgram prog_pool[MAX_PROCESSES]; // Memory for loaded code

// ============================================================
// Enhanced Object I/O (TVM3 - with hardware support)
// ============================================================
struct TVMObject {
    static int save(uint64_t base, int port, const char* path, const TProgram& P){
        static unsigned char buf[ TProgram::CODE_MAX + TProgram::LIT_MAX + 128 ];
        int off=0;
        buf[off++]='T'; buf[off++]='V'; buf[off++]='M'; buf[off++]='3'; // Version 3 with hardware support
        *(int*)&buf[off]=P.pc; off+=4;
        *(int*)&buf[off]=P.lit_top; off+=4;
        *(int*)&buf[off]=P.loc_count; off+=4;
        simple_memcpy(&buf[off], P.code, P.pc); off+=P.pc;
        simple_memcpy(&buf[off], P.lit, P.lit_top); off+=P.lit_top;

        // Save local variable metadata (names, types, array sizes)
        for(int i = 0; i < P.loc_count; i++) {
            int name_len = tcc_strlen(P.loc_name[i]) + 1;
            simple_memcpy(&buf[off], P.loc_name[i], name_len); off += name_len;
            buf[off++] = P.loc_type[i];
            *(int*)&buf[off] = P.loc_array_size[i]; off += 4;
        }

        return fat32_write_file(path, buf, off);
    }

    // In SECTION 6, inside the TVMObject struct

static int load(uint64_t base, int port, const char* path, TProgram& P){
    // FIX: First, get the file's directory entry to find its true size.
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    if (fat32_find_entry(path, &entry, &sector, &offset) != 0) {
        return -1; // File not found
    }
    uint32_t n = entry.file_size; // Use the REAL size from the filesystem.

    // Now we can read the file content.
    char* buf = fat32_read_file_as_string(path);
    if (!buf) {
        return -1; // Read failed
    }

    // The original buggy line is no longer needed.
    // int n = tcc_strlen(buf);  

    if (n < 16) { 
        delete[] buf; 
        return -1; 
    }
    if (!(buf[0] == 'T' && buf[1] == 'V' && buf[2] == 'M' && (buf[3] == '1' || buf[3] == '2' || buf[3] == '3'))) {
        delete[] buf;
        return -2;
    }
    int cp = *(int*)&buf[4], lp = *(int*)&buf[8], lc = *(int*)&buf[12];
    if (cp < 0 || cp > TProgram::CODE_MAX || lp < 0 || lp > TProgram::LIT_MAX || lc < 0 || lc > TProgram::LOC_MAX) {
        delete[] buf;
        return -3;
    }

    // The rest of the function now works correctly because 'n' is the true file size.
    P.pc = cp; P.lit_top = lp; P.loc_count = lc;
    int off = 16;
    simple_memcpy(P.code, &buf[off], cp); off += cp;
    simple_memcpy(P.lit, &buf[off], lp); off += lp;

    if (buf[3] >= '2') {
        for (int i = 0; i < lc; i++) {
            int name_len = 0;
            while (off + name_len < n && buf[off + name_len] != 0) name_len++;
            
            if (name_len < 32) {
                simple_memcpy(P.loc_name[i], &buf[off], name_len + 1);
            } else {
                P.loc_name[i][0] = 0;
            }
            off += name_len + 1;
            
            // Boundary check before reading type and size
            if (off + 5 > n) {
                delete[] buf;
                return -4; // Corrupt file, not enough data for metadata
            }
            
            P.loc_type[i] = buf[off++];
            P.loc_array_size[i] = *(int*)&buf[off]; off += 4;
        }
    } else {
        for (int i = 0; i < lc; i++) {
            P.loc_name[i][0] = 0;
            P.loc_type[i] = 0;
            P.loc_array_size[i] = 0;
        }
    }
    delete[] buf;
    return 0;
};
};

// ============================================================
// Enhanced compile/run entry points
// ============================================================
static int tinyvm_compile_to_obj(uint64_t ahci_base, int port, const char* src_path, const char* obj_path){
    char* srcbuf = fat32_read_file_as_string(src_path);
    if(!srcbuf){ printf("read fail\n"); return -1; }
    TCompiler C; int ok = C.compile(srcbuf);
    delete[] srcbuf;
    if(ok<0){ printf("Compilation failed!\n"); return -2; }
    int w = TVMObject::save(ahci_base, port, obj_path, C.pr);
    if(w<0){ printf("write fail\n"); return -3; }
    return 0;
}
// Updated wrapper (optional)
static int tinyvm_run_obj(uint64_t ahci_base, int port, const char* obj_path, int argc, const char** argv) {
    // Forward the actual parameters passed to this function
    cmd_run(ahci_base, port, obj_path);
    return 0;
}



// ============================================================
// Enhanced Shell glue with hardware discovery info
// ============================================================
extern "C" void cmd_compile(uint64_t ahci_base, int port, const char* filename){
    if (!filename) { printf("Usage: compile <file.cpp>\n"); return; }
    static char obj[64]; int i=0; while(filename[i] && i<60){ obj[i]=filename[i]; i++; }
    while(i>0 && obj[i-1] != '.') i--; obj[i]=0; simple_strcpy(&obj[i], "obj");
    printf("Compiling %s...\n", filename);
    int r = tinyvm_compile_to_obj(ahci_base, port, filename, obj);
    if(r==0) { printf("OK -> %s\n", obj); } else { printf("Compilation failed!\n"); }
}


// --- Command parsing helper ---
char* get_arg(char* args, int n) {
    char* p = args;

    // Loop to find the start of the Nth argument
    for (int i = 0; i < n; i++) {
        // Skip leading spaces for the current argument
        while (*p && *p == ' ') p++;

        // If we're at the end of the string, the requested arg doesn't exist
        if (*p == '\0') return nullptr;

        // Skip over the content of the current argument
        if (*p == '"') {
            p++; // Skip opening quote
            while (*p && *p != '"') p++;
            if (*p == '"') p++; // Skip closing quote
        } else {
            while (*p && *p != ' ') p++;
        }
    }

    // Now p is at the start of the Nth argument (or spaces before it)
    while (*p && *p == ' ') p++;
    if (*p == '\0') return nullptr;

    char* arg_start = p;
    if (*p == '"') {
        arg_start++; // The actual argument starts after the quote
        p++;
        while (*p && *p != '"') p++;
        if (*p == '"') *p = '\0'; // Place null terminator on the closing quote
    } else {
        while (*p && *p != ' ') p++;
        if (*p) *p = '\0'; // Place null terminator on the space
    }
    return arg_start;
}


    // Separate process tables
#define MAX_RUN_PROCESSES 4
#define MAX_EXEC_PROCESSES 4

// Context for RUN processes (disk-based execution)
struct RunContext {
    TProgram prog;           // Program code
    uint64_t ahci_base;      // Disk controller base
    int port;                // Disk port
    TinyVM vm;               // VM instance
    bool active;             // Is this slot in use
    char filename[64];       // Source filename for debugging
};

// Context for EXEC processes (memory-based execution)  
struct ExecContext {
    TProgram prog;           // Program code
    TinyVM vm;               // VM instance
    bool active;             // Is this slot in use
    int exec_id;             // Unique execution ID
};
static RunContext run_contexts[MAX_RUN_PROCESSES];
static ExecContext exec_contexts[MAX_EXEC_PROCESSES];
	
	// List active run processes
void list_run_processes() {
    wm.print_to_focused("Active RUN processes:\n");
    bool found = false;
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (run_contexts[i].active) {
            char msg[128];
            snprintf(msg, 128, "  Slot %d: %s (IP=%d)\n", 
                     i, run_contexts[i].filename, run_contexts[i].vm.ip);
            wm.print_to_focused(msg);
            found = true;
        }
    }
    if (!found) {
        wm.print_to_focused("  (none)\n");
    }
}




// List active exec processes
void list_exec_processes() {
    wm.print_to_focused("Active EXEC processes:\n");
    bool found = false;
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        if (exec_contexts[i].active) {
            char msg[128];
            snprintf(msg, 128, "  Slot %d: ID=%d (IP=%d)\n", 
                     i, exec_contexts[i].exec_id, exec_contexts[i].vm.ip);
            wm.print_to_focused(msg);
            found = true;
        }
    }
    if (!found) {
        wm.print_to_focused("  (none)\n");
    }
}

// Kill a run process
void kill_run_process(int slot) {
    if (slot >= 0 && slot < MAX_RUN_PROCESSES && run_contexts[slot].active) {
        run_contexts[slot].active = false;
        run_contexts[slot].vm.is_running = false;
        wm.print_to_focused("RUN process killed.\n");
    } else {
        wm.print_to_focused("Invalid RUN slot.\n");
    }
}

// Kill an exec process
void kill_exec_process(int slot) {
    if (slot >= 0 && slot < MAX_EXEC_PROCESSES && exec_contexts[slot].active) {
        exec_contexts[slot].active = false;
        exec_contexts[slot].vm.is_running = false;
        wm.print_to_focused("EXEC process killed.\n");
    } else {
        wm.print_to_focused("Invalid EXEC slot.\n");
    }
}
	
	

	
bool run_process_waiting_for_input() {
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (run_contexts[i].active && run_contexts[i].vm.waiting_for_input) {
            return true;
        }
    }
    return false;
}
		
	// =============================================================================
// ELF32 LOADER AND PROCESS EXECUTION
// =============================================================================

// ELF32 Header structures
#define EI_NIDENT 16
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS32 1
#define ELFDATA2LSB 1

#define ET_EXEC 2
#define EM_386 3

#define PT_LOAD 1
#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} __attribute__((packed)) Elf32_Phdr;

// Process structure for ELF execution
#define MAX_ELF_PROCESSES 4
#define ELF_STACK_SIZE (64 * 1024)  // 64KB stack per process
#define ELF_HEAP_SIZE (256 * 1024)   // 256KB heap per process
// REPLACE existing ElfProcess struct with:
struct ElfProcess {
    bool active;
    uint32_t entry_point;
    uint8_t* memory_base;
    uint32_t memory_size;
    uint8_t* stack;
    uint32_t esp;
    uint32_t eip;
    TerminalWindow* terminal;
    char cmdline[256];
    bool waiting_for_input;
    char input_buffer[256];
    int input_pos;
    bool completed;
    int exit_code;

    // ── I/O ring buffer (terminal → process) ──────────────────────────
    static const int IN_BUF_SIZE = 512;
    char  in_buf[IN_BUF_SIZE];
    int   in_head = 0;   // producer (terminal writes here)
    int   in_tail = 0;   // consumer (process reads here)

    // ── Output ring buffer (process → terminal) ────────────────────────
    static const int OUT_BUF_SIZE = 4096;
    char  out_buf[OUT_BUF_SIZE];
    int   out_head = 0;  // producer (process writes here)
    int   out_tail = 0;  // consumer (terminal reads here)

    // ── helpers ───────────────────────────────────────────────────────
    bool in_empty()  const { return in_head  == in_tail;  }
    bool out_empty() const { return out_head == out_tail; }

    void push_input(char c) {
        int next = (in_head + 1) % IN_BUF_SIZE;
        if (next != in_tail) { in_buf[in_head] = c; in_head = next; }
    }
    char pop_input() {
        if (in_empty()) return 0;
        char c = in_buf[in_tail];
        in_tail = (in_tail + 1) % IN_BUF_SIZE;
        return c;
    }
    void push_output(char c) {
        int next = (out_head + 1) % OUT_BUF_SIZE;
        if (next != out_tail) { out_buf[out_head] = c; out_head = next; }
    }
    char pop_output() {
        if (out_empty()) return 0;
        char c = out_buf[out_tail];
        out_tail = (out_tail + 1) % OUT_BUF_SIZE;
        return c;
    }
    void push_output_str(const char* s) {
        while (s && *s) push_output(*s++);
    }
};

static ElfProcess elf_processes[MAX_ELF_PROCESSES];
// =============================================================================
// TERMINAL WINDOW IMPLEMENTATION
// =============================================================================
static constexpr int TERM_HEIGHT = 35;
static constexpr int TERM_WIDTH  = 120;
char prompt_buffer[TERM_WIDTH];

class TerminalWindow : public Window {
private:
    // Terminal state
    char buffer[TERM_HEIGHT][TERM_WIDTH];
    int line_count;
    char current_line[TERM_WIDTH];
    int line_pos;

    // Editor state
    bool in_editor;
    char edit_filename[32];
    char** edit_lines;
    int edit_line_count;
    int edit_current_line;
    int edit_cursor_col;
    int edit_scroll_offset;

    // Prompt visual state for multi-line input
    int prompt_visual_lines;
// Editor viewport settings
static constexpr int EDIT_ROWS = 35;       // rows visible in the editor area
static constexpr int EDIT_COL_PIX = 8;     // font width
static constexpr int EDIT_LINE_PIX = 10;   // line height
void put_char(char c) {
        if (in_editor) return; // Don't mess with editor

        // Ensure we have at least one line
        if (line_count == 0) {
            push_line("");
        }

        // Get the last line in the buffer
        char* line = buffer[line_count - 1];
        int len = strlen(line);

        if (c == '\n') {
            push_line(""); // Real newline
        } 
        else if (c == '\b') {
            if (len > 0) {
                line[len - 1] = 0; // Remove last char
            }
        } 
        else if (c >= 32 && c <= 126) {
            // Check if line is full
            if (len < TERM_WIDTH - 1) {
                line[len] = c;
                line[len + 1] = 0;
            } else {
                // Wrap to new line
                char temp[2] = {c, 0};
                push_line(temp);
            }
        }
    }
void editor_clamp_cursor_to_line() {
    if (edit_current_line < 0) edit_current_line = 0;
    if (edit_current_line >= edit_line_count) edit_current_line = edit_line_count - 1;
    if (edit_current_line < 0) edit_current_line = 0; // handle empty
    if (edit_line_count > 0) {
        int len = (int)strlen(edit_lines[edit_current_line]);
        if (edit_cursor_col > len) edit_cursor_col = len;
        if (edit_cursor_col < 0) edit_cursor_col = 0;
    } else {
        edit_cursor_col = 0;
    }
}

void editor_ensure_cursor_visible() {
    if (edit_current_line < edit_scroll_offset) {
        edit_scroll_offset = edit_current_line;
        if (edit_scroll_offset < 0) edit_scroll_offset = 0;
    } else if (edit_current_line >= edit_scroll_offset + EDIT_ROWS) {
        edit_scroll_offset = edit_current_line - (EDIT_ROWS - 1);
    }
}
private:
    // Insert a new line at a given index, copying the provided text into it.
    void editor_insert_line_at(int index, const char* text) {
        if (index < 0 || index > edit_line_count) return;

        char** new_lines = new char*[edit_line_count + 1];

        for (int i = 0; i < index; ++i) {
            new_lines[i] = edit_lines[i];
        }

        new_lines[index] = new char[TERM_WIDTH];
        memset(new_lines[index], 0, TERM_WIDTH);
        if (text) {
            strncpy(new_lines[index], text, TERM_WIDTH - 1);
        }

        for (int i = index; i < edit_line_count; ++i) {
            new_lines[i + 1] = edit_lines[i];
        }

        if (edit_lines) {
            delete[] edit_lines;
        }
        edit_lines = new_lines;
        edit_line_count++;
    }

    // Delete the line at a given index.
    void editor_delete_line_at(int index) {
        if (index < 0 || index >= edit_line_count || edit_line_count <= 1) return;

        delete[] edit_lines[index];

        char** new_lines = new char*[edit_line_count - 1];
        
        for (int i = 0; i < index; ++i) {
            new_lines[i] = edit_lines[i];
        }

        for (int i = index + 1; i < edit_line_count; ++i) {
            new_lines[i - 1] = edit_lines[i];
        }

        delete[] edit_lines;
        edit_lines = new_lines;
        edit_line_count--;
    }

    // Get visible columns for the first prompt line (accounts for "> ")
    int term_cols_first() const {
        int cols = (w - 10) / 8;
        cols -= 2;
        if (cols < 1) cols = 1;
        if (cols > 118) cols = 118;
        return cols;
    }

    // Get visible columns for continuation lines or general output
    int term_cols_cont() const {
        int cols = (w - 10) / 8;
        if (cols < 1) cols = 1;
        if (cols > 118) cols = 118;
        return cols;
    }

    // Removes the last N lines from the terminal buffer (used to refresh prompt)
    void remove_last_n_lines(int n) {
        while (n-- > 0 && line_count > 0) {
            memset(buffer[line_count - 1], 0, 120);
            line_count--;
        }
    }

    // Finds the best position to wrap a string within max_cols
    int find_wrap_pos(const char* s, int max_cols) {
        int len = (int)strlen(s);
        if (len <= max_cols) return len;

        int wrap_at = max_cols;
        for (int i = max_cols; i > 0; --i) {
            if (s[i] == ' ' || s[i] == '\t' || s[i] == '-') {
                wrap_at = i;
                break;
            }
        }
        return wrap_at;
    }

    // Pushes a single line segment of the prompt to the terminal buffer
    void append_prompt_line(const char* seg, bool first) {
        char linebuf[120];
        linebuf[0] = 0;
        if (first) {
            snprintf(linebuf, 120, "> %s", seg);
        } else {
            snprintf(linebuf, 120, "  %s", seg);
        }
        push_line(linebuf);
    }

    // Redraws the entire multi-line prompt based on `current_line`
    void update_prompt_display() {
        if (prompt_visual_lines > 0) {
            remove_last_n_lines(prompt_visual_lines);
            prompt_visual_lines = 0;
        }

        const char* p = current_line;
        bool first = true;
        int seg_count = 0;

        if (*p == '\0') {
            append_prompt_line("", true);
            prompt_visual_lines = 1;
            return;
        }

        while (*p) {
            int max_cols = first ? term_cols_first() : term_cols_cont();
            int take = find_wrap_pos(p, max_cols);

            char seg[120];
            strncpy(seg, p, take);
            seg[take] = '\0';
            
            int trim = (int)strlen(seg);
            while (trim > 0 && (seg[trim-1] == ' ' || seg[trim-1] == '\t')) {
                seg[--trim] = '\0';
            }

            append_prompt_line(seg, first);
            seg_count++;

            p += take;
            if (*p == ' ' || *p == '\t') p++;
            first = false;
        }
        prompt_visual_lines = seg_count;
    }

    // Pushes word-wrapped text (from console_print) to the buffer
    void push_wrapped_text(const char* s, int cols) {
        const char* p = s;
        while (*p) {
            const char* nl = strchr(p, '\n');
            if (!nl) nl = p + strlen(p);

            char line[512]; // Temporary buffer for a logical line
            int len = nl - p;
            if (len > 511) len = 511;
            strncpy(line, p, len);
            line[len] = '\0';

            const char* q = line;
            if (*q == '\0' && nl != p) {
                push_line(""); // Preserve blank lines
            } else {
                while (*q) {
                    int take = find_wrap_pos(q, cols);
                    char seg[120];
                    strncpy(seg, q, take);
                    seg[take] = '\0';

                    int trim = (int)strlen(seg);
                        while (trim > 0 && (seg[trim-1] == ' ' || seg[trim-1] == '\t')) {
                            seg[--trim] = '\0';
                    }

                    push_line(seg);
                    q += take;
                    if (*q == ' ' || *q == '\t') q++;
                }
            }
            p = (*nl == '\n') ? nl + 1 : nl;
        }
    }

    // --- END OF MODULE ---

    void scroll() {
        memmove(buffer[0], buffer[1], (TERM_HEIGHT - 1) * TERM_WIDTH);
        memset(buffer[TERM_HEIGHT - 1], 0, TERM_WIDTH);
    }

    void push_line(const char* s) {
        if (line_count >= TERM_HEIGHT) {
            scroll();
            strncpy(buffer[TERM_HEIGHT - 1], s, TERM_WIDTH - 1);
        } else {
            strncpy(buffer[line_count], s, TERM_WIDTH - 1);
            line_count++;
        }
    }
    void print_prompt() { 
        snprintf(prompt_buffer, TERM_WIDTH, "> %s", current_line);
        if (line_count > 0) {
            strncpy(buffer[line_count-1], prompt_buffer, TERM_WIDTH - 1);
        } else {
            push_line(prompt_buffer);
        }
    }
	
// =============================================================================
// AES-128 ENCRYPTION - GLOBAL (PLACE BEFORE WINDOW CLASS)
// =============================================================================
// AES S-box (256 entries)
static constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box (256 entries)
static constexpr uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static constexpr uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


class AES128 {
private:
    uint8_t round_keys[176];
    uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
    void key_expansion(const uint8_t* key) {
        memcpy(round_keys, key, 16);
        for (int i = 4; i < 44; i++) {
            uint8_t temp[4];
            memcpy(temp, &round_keys[(i-1)*4], 4);
            if (i % 4 == 0) {
                uint8_t k = temp[0];
                temp[0] = sbox[temp[1]] ^ rcon[i/4];
                temp[1] = sbox[temp[2]];
                temp[2] = sbox[temp[3]];
                temp[3] = sbox[k];
            }
            for (int j = 0; j < 4; j++) round_keys[i*4 + j] = round_keys[(i-4)*4 + j] ^ temp[j];
        }
    }
    void add_round_key(uint8_t* state, int round) {
        for (int i = 0; i < 16; i++) state[i] ^= round_keys[round * 16 + i];
    }
    void sub_bytes(uint8_t* state) { for (int i = 0; i < 16; i++) state[i] = sbox[state[i]]; }
    void inv_sub_bytes(uint8_t* state) { for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]]; }
    void shift_rows(uint8_t* state) {
        uint8_t temp;
        temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
    }
    void inv_shift_rows(uint8_t* state) {
        uint8_t temp;
        temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
    }
    void mix_columns(uint8_t* state) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
            state[i*4]   = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
            state[i*4+1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
            state[i*4+2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
            state[i*4+3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
        }
    }
    void inv_mix_columns(uint8_t* state) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
            state[i*4]   = xtime(xtime(xtime(s0) ^ s0) ^ xtime(xtime(s1))) ^ xtime(xtime(s2) ^ s2) ^ xtime(s3) ^ s3;
            state[i*4+1] = xtime(s0) ^ s0 ^ xtime(xtime(xtime(s1) ^ s1) ^ xtime(xtime(s2))) ^ xtime(xtime(s3) ^ s3);
            state[i*4+2] = xtime(xtime(s0) ^ s0) ^ xtime(s1) ^ s1 ^ xtime(xtime(xtime(s2) ^ s2) ^ xtime(xtime(s3)));
            state[i*4+3] = xtime(xtime(xtime(s0))) ^ xtime(xtime(s1) ^ s1) ^ xtime(s2) ^ s2 ^ xtime(xtime(xtime(s3) ^ s3));
        }
    }
public:
    void set_key(const uint8_t* key) { key_expansion(key); }
    void encrypt_block(uint8_t* block) {
        add_round_key(block, 0);
        for (int round = 1; round < 10; round++) {
            sub_bytes(block); shift_rows(block); mix_columns(block); add_round_key(block, round);
        }
        sub_bytes(block); shift_rows(block); add_round_key(block, 10);
    }
    void decrypt_block(uint8_t* block) {
        add_round_key(block, 10);
        for (int round = 9; round > 0; round--) {
            inv_shift_rows(block); inv_sub_bytes(block); add_round_key(block, round); inv_mix_columns(block);
        }
        inv_shift_rows(block); inv_sub_bytes(block); add_round_key(block, 0);
    }
};

void hex_to_bytes(const char* hex, uint8_t* bytes, int len) {
    for (int i = 0; i < len; i++) {
        uint8_t high = hex[i*2], low = hex[i*2+1];
        if (high >= '0' && high <= '9') high = high - '0';
        else if (high >= 'a' && high <= 'f') high = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F') high = high - 'A' + 10;
        if (low >= '0' && low <= '9') low = low - '0';
        else if (low >= 'a' && low <= 'f') low = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F') low = low - 'A' + 10;
        bytes[i] = (high << 4) | low;
    }
}

void bytes_to_hex(const uint8_t* bytes, char* hex, int len) {
    const char* hex_chars = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex[i*2] = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[i*2+1] = hex_chars[bytes[i] & 0xF];
    }
    hex[len*2] = '\0';
}

void pkcs7_pad(uint8_t* data, size_t len) {
    size_t pad_len = 16 - (len % 16);
    for (size_t i = 0; i < pad_len; ++i) data[len + i] = static_cast<uint8_t>(pad_len);
}

bool pkcs7_unpad(uint8_t* data, size_t& len) {
    if (len == 0) return false;
    size_t pad_len = data[len - 1];
    if (pad_len > 16 || pad_len > len) return false;
    for (size_t i = 1; i <= pad_len; ++i) {
        if (data[len - i] != static_cast<uint8_t>(pad_len)) return false;
    }
    len -= pad_len;
    return true;
}

bool aes_encrypt_file(const char* key_hex, const char* infile, const char* outfile) {
    char* content = fat32_read_file_as_string(infile);
    if (!content) return false;
    size_t len = strlen(content);
    size_t padded_len = ((len + 15) / 16) * 16;
    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, content, len);
    pkcs7_pad(padded, len);
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);
    AES128 aes; aes.set_key(key);
    for (size_t i = 0; i < padded_len / 16; ++i) aes.encrypt_block(padded + i * 16);
    int result = fat32_write_file(outfile, padded, static_cast<uint32_t>(padded_len));
    delete[] padded; delete[] content;
    return result == 0;
}

bool aes_decrypt_file(const char* key_hex, const char* infile, const char* outfile) {
    char* enc_content = fat32_read_file_as_string(infile);
    if (!enc_content) return false;
    size_t enc_len = strlen(enc_content);
    if (enc_len % 16 != 0) { delete[] enc_content; return false; }
    uint8_t* data = reinterpret_cast<uint8_t*>(enc_content);
    uint8_t key[16]; hex_to_bytes(key_hex, key, 16);
    AES128 aes; aes.set_key(key);
    for (size_t i = 0; i < enc_len / 16; ++i) aes.decrypt_block(data + i * 16);
    if (!pkcs7_unpad(data, enc_len)) { delete[] enc_content; return false; }
    int result = fat32_write_file(outfile, data, static_cast<uint32_t>(enc_len));
    delete[] enc_content;
    return result == 0;
}	
char startup_command_buffer[256];




// Find free process slot
int find_free_elf_slot() {
    for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
        if (!elf_processes[i].active) {
            return i;
        }
    }
    return -1;
}

// Validate ELF header
bool validate_elf_header(const Elf32_Ehdr* ehdr) {
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return false;
    }
    
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        return false;
    }
    
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return false;
    }
    
    if (ehdr->e_type != ET_EXEC) {
        return false;
    }
    
    if (ehdr->e_machine != EM_386) {
        return false;
    }
    
    return true;
}


bool disk_has_password() {
    if (!ahci_base || !current_directory_cluster) return false;
    // Probe raw — directory must be readable before unlock.
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    bool found = (fat32_find_entry(g_disk_password_file, &entry, &sector, &offset) == 0);
    g_fs_encryption_enabled = was_enabled;
    return found;
}
// Kill an ELF process
void kill_elf_process(int slot) {
    if (slot >= 0 && slot < MAX_ELF_PROCESSES && elf_processes[slot].active) {
        if (elf_processes[slot].memory_base) {
            delete[] elf_processes[slot].memory_base;
        }
        if (elf_processes[slot].stack) {
            delete[] elf_processes[slot].stack;
        }
        elf_processes[slot].active = false;
        elf_processes[slot].memory_base = nullptr;
        elf_processes[slot].stack = nullptr;
    }
}

// List ELF processes
void list_elf_processes(TerminalWindow* terminal) {
    if (!terminal) return;
    
    terminal->console_print("Active ELF processes:\n");
    bool found = false;
    for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
        if (elf_processes[i].active) {
            char msg[128];
            snprintf(msg, 128, "  Slot %d: entry=0x%x mem=%d KB cmd=%s\n", 
                     i, 
                     elf_processes[i].entry_point,
                     elf_processes[i].memory_size / 1024,
                     elf_processes[i].cmdline);
            terminal->console_print(msg);
            found = true;
        }
    }
    if (!found) {
        terminal->console_print("  (none)\n");
    }
}


// =============================================================================
// DISK PASSWORD SYSTEM
// =============================================================================

static uint32_t simple_hash(const char* str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;
    }
    return hash;
}

static void hash_to_hex(uint32_t hash, char* out) {
    const char* hex = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) {
        out[i] = hex[hash & 0xF];
        hash >>= 4;
    }
    out[8] = '\0';
}
bool disk_check_password(const char* attempt) {
    // Read raw — the password file is always plaintext on disk.
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;
    char* stored = fat32_read_file_as_string(g_disk_password_file);
    g_fs_encryption_enabled = was_enabled;

    if (!stored) return false;

    uint32_t hash = simple_hash(attempt);
    char hex[9];
    hash_to_hex(hash, hex);
    bool match = (strncmp(stored, hex, 8) == 0);
    delete[] stored;

    if (match) fs_crypto_init(attempt);
    return match;
}
bool disk_set_password(const char* password) {
    if (!password || password[0] == '\0') return false;
    if (strlen(password) < 4) return false;

    // 1. Make sure crypto is OFF so the write goes to disk plaintext.
    //    The password file must always be written unencrypted because
    //    disk_has_password() and disk_check_password() probe it raw.
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;

    // 2. Compute and write the hash record unencrypted.
    uint32_t hash = simple_hash(password);
    char hex[9];
    hash_to_hex(hash, hex);
    bool ok = (fat32_write_file(g_disk_password_file, hex, 8) == 0);

    // 3. Only arm encryption if the write succeeded.
    if (ok) {
        fs_crypto_init(password);
        g_fs_encryption_enabled = true;
    } else {
        g_fs_encryption_enabled = was_enabled;
        fs_crypto_clear();
    }

    return ok;
}
bool disk_remove_password(const char* current_password) {
    if (!disk_check_password(current_password)) return false;

    // Disarm crypto first so the remove operates on the plaintext directory.
    fs_crypto_clear();
    g_fs_encryption_enabled = false;

    fat32_remove_file(g_disk_password_file);
    g_disk_unlocked = false;
    return true;
}


// Guards all disk-touching commands — returns true if access is allowed
bool disk_access_allowed(TerminalWindow* term) {
    if (!disk_has_password()) return true;   // no password set → open
    if (g_disk_unlocked) return true;         // already authenticated this session
    if (term) term->console_print("Disk is locked. Use: unlock <password>\n");
    return false;
}


// --- Terminal command handler ---
void handle_command() {
    int selected_port = 0;
    char cmd_line[120];
    strncpy(cmd_line, current_line, 119);
    cmd_line[119] = '\0';

    char* command = cmd_line;
    while (*command && *command == ' ') {
        command++;
    }

    if (*command == '\0') {
        if (!in_editor) print_prompt();
        return;
    }

    char* args = command;
    while (*args && *args != ' ') {
        args++;
    }
    if (*args) {
        *args = '\0'; 
        args++;       
        while (*args && *args == ' ') {
            args++;
        }
    }

	if (strcmp(command, "help") == 0) {
		console_print("Commands: help, clear, version, time, ps, ls, edit, run, exec,\n"
					  "  compile, rm, cp, mv, formatfs, chkdsk (/r /f), select_disk,\n"
					  "  setpass, removepass, unlock, busybox, pself, killelf,\n"
					  "  killexec, killrun, aesenc, aesdec\n");
	}
	else if (strcmp(command, "aesenc") == 0 || strcmp(command, "aesdec") == 0) {
        bool encrypt = strcmp(command, "aesenc") == 0;
        char* key_hex = get_arg(args, 0);
        char* infile = get_arg(args, 1);
        char* outfile = get_arg(args, 2);
        if (!key_hex || !infile || !outfile || strlen(key_hex) != 32) {
            console_print(encrypt ? "Usage: aesenc <32hexkey> <in> <out>\n" : "Usage: aesdec <32hexkey> <in> <out>\n");
            return;
        }
        bool ok = encrypt ? aes_encrypt_file(key_hex, infile, outfile) : aes_decrypt_file(key_hex, infile, outfile);
        console_print(ok ? "AES operation successful.\n" : "AES failed.\n");
    }
	else if (strcmp(command, "select_disk") == 0) {
		g_disk_unlocked = false;
		fs_crypto_clear();                   // wipe key on disk switch
		cmd_list_and_select_disk(args);
		if (disk_has_password())
			console_print("This disk is password protected. Use: unlock <password>\n");
	}

	else if (strcmp(command, "unlock") == 0) {
		if (!disk_has_password()) {
			console_print("No password set. Use: setpass <password>\n");
		} else if (g_disk_unlocked) {
			console_print("Disk already unlocked.\n");
		} else {
			char* pw = get_arg(args, 0);
			if (!pw) {
				console_print("Usage: unlock <password>\n");
			} else if (disk_check_password(pw)) {  // arms crypto internally
				g_disk_unlocked = true;
				console_print("Disk unlocked and decryption armed.\n");
			} else {
				console_print("Wrong password.\n");
			}
		}
	}
	if (strcmp(command, "compile") == 0) {
        cmd_compile(ahci_base, selected_port, get_arg(args, 0));
    } else if (strcmp(command, "busybox") == 0) {
        // Launch busybox with optional arguments
        if (args && strlen(args) > 0) {
            // Check if busybox file exists, if not extract it
            char* test_data = fat32_read_file_as_string("busybox");
            if (!test_data) {
                console_print("BusyBox not found. Extracting from embedded image...\n");
                if (extract_busybox_to_filesystem()) {
                    console_print("BusyBox extracted successfully.\n");
                } else {
                    console_print("Failed to extract BusyBox.\n");
                    return;
                }
            } else {
                delete[] test_data;
            }
            
            // Load and execute BusyBox ELF
            console_print("Loading BusyBox: ");
            console_print(args);
            console_print("\n");
            
            // Build full command line
            char full_args[256];
            snprintf(full_args, 256, "busybox %s", args);
            
            int slot = load_and_execute_elf("busybox", full_args, this);
            if (slot >= 0) {
                console_print("BusyBox loaded successfully\n");
            }
        } else {
            console_print("Usage: busybox <command> [args]\n");
            console_print("Example: busybox ls\n");
            console_print("         busybox sh\n");
            console_print("Available commands: ");
            console_print("ls, cat, echo, sh, grep, find, etc.\n");
        }
    } else if (strcmp(command, "pself") == 0) {
        // List ELF processes
        list_elf_processes(this);
    } else if (strcmp(command, "killelf") == 0) {
        // Kill an ELF process
        char* arg = get_arg(args, 0);
        if (arg) {
            int slot = simple_atoi(arg);
            kill_elf_process(slot);
            console_print("ELF process killed\n");
        } else {
            console_print("Usage: killelf <slot>\n");
        }
    } else if (strcmp(command, "run") == 0) {
        cmd_run(ahci_base, selected_port, get_arg(args, 0));
    }
    else if (strcmp(command, "exec") == 0) {
        cmd_exec(get_arg(args, 0));
    }
    else if (strcmp(command, "ps") == 0) {
        list_run_processes();
        list_exec_processes();
    }
    else if (strcmp(command, "killrun") == 0) {
        kill_run_process(simple_atoi(get_arg(args, 0)));
    }
    else if (strcmp(command, "killexec") == 0) {
        kill_exec_process(simple_atoi(get_arg(args, 0)));
    }
	
	else if (strcmp(command, "setpass") == 0) {
		// Allowed even when locked so the first password can be set,
		// but changing an existing password requires unlock first.
		if (disk_has_password() && !g_disk_unlocked) {
			console_print("Disk locked. Unlock before changing password.\n");
		} else {
			char* pw = get_arg(args, 0);
			if (!pw || strlen(pw) < 4) {
				console_print("Usage: setpass <password>  (min 4 chars)\n");
			} else {
				if (disk_set_password(pw)) {
					g_disk_unlocked = true; // creator is implicitly unlocked
					console_print("Password set. Disk is now protected.\n");
				} else {
					console_print("Failed to write password file.\n");
				}
			}
		}
	}
	else if (strcmp(command, "removepass") == 0) {
		char* pw = get_arg(args, 0);
		if (!pw) {
			console_print("Usage: removepass <current_password>\n");
		} else if (disk_remove_password(pw)) {
			g_disk_unlocked = false; // reset session state
			console_print("Password removed. Disk is now open.\n");
		} else {
			console_print("Wrong password.\n");
		}
	}
    else if (strcmp(command, "clear") == 0) { line_count = 0; memset(buffer, 0, sizeof(buffer)); }
    else if (strcmp(command, "ls") == 0) { fat32_list_files(); }
    else if (strcmp(command, "edit") == 0) {
        char* filename = get_arg(args, 0);
        if(filename) {
            strncpy(edit_filename, filename, 31);
            edit_filename[31] = '\0';
            in_editor = true;
            edit_current_line = 0;
            edit_cursor_col = 0;
            edit_scroll_offset = 0;
            char* content = fat32_read_file_as_string(filename);
            if (content) {
                int line_count_temp = 1;
                for (char* p = content; *p; p++) if (*p == '\n') line_count_temp++;
                
                edit_lines = new char*[line_count_temp];
                edit_line_count = 0;
                
                char* line_start = content;
                for (char* p = content; *p; p++) {
                    if (*p == '\n') {
                        *p = '\0';
                        edit_lines[edit_line_count] = new char[120];
                        memset(edit_lines[edit_line_count], 0, 120);
                        strncpy(edit_lines[edit_line_count], line_start, 119);
                        edit_line_count++;
                        line_start = p + 1;
                    }
                }
                if (*line_start) {
                    edit_lines[edit_line_count] = new char[120];
                    memset(edit_lines[edit_line_count], 0, 120);
                    strncpy(edit_lines[edit_line_count], line_start, 119);
                    edit_line_count++;
                }
                delete[] content;
            } else {
                edit_lines = new char*[1];
                edit_lines[0] = new char[120];
                memset(edit_lines[0], 0, 120);
                edit_line_count = 1;
            }
        } else {
            console_print("Usage: edit \"<filename>\"\n");
        }
    }
    
    else if (strcmp(command, "rm") == 0) { 
        char* filename = get_arg(args, 0); 
        if(filename) { 
            if(fat32_remove_file(filename) == 0) 
                console_print("File removed.\n"); 
            else 
                console_print("Failed to remove file.\n");
        } else { 
            console_print("Usage: rm \"<filename>\"\n");
        }
    }
    else if (strcmp(command, "cp") == 0) {
        char args_for_src[120];
        strncpy(args_for_src, args, 119);
        char* src = get_arg(args_for_src, 0);

        char args_for_dest[120];
        strncpy(args_for_dest, args, 119);
        char* dest = get_arg(args_for_dest, 1);
        
        if(!src || !dest) { 
            console_print("Usage: cp \"<source>\" \"<dest>\"\n"); 
        } else {
            fat_dir_entry_t entry;
            uint32_t sector, offset;
            if (fat32_find_entry(src, &entry, &sector, &offset) == 0) {
                char* content = new char[entry.file_size];
                if (content && read_data_from_clusters((entry.fst_clus_hi << 16) | entry.fst_clus_lo, content, entry.file_size)) {
                    if(fat32_write_file(dest, content, entry.file_size) == 0) {
                        console_print("Copied.\n");
                    } else {
                        console_print("Write failed.\n");
                    }
                } else {
                    console_print("Read failed.\n");
                }
                if (content) delete[] content;
            } else {
                console_print("Source not found.\n");
            }
        }
    }
    else if (strcmp(command, "mv") == 0) {
        char args_for_src[120];
        strncpy(args_for_src, args, 119);
        char* src = get_arg(args_for_src, 0);

        char args_for_dest[120];
        strncpy(args_for_dest, args, 119);
        char* dest = get_arg(args_for_dest, 1);

        if(!src || !dest) { 
            console_print("Usage: mv \"<source>\" \"<dest>\"\n"); 
        } else {
            if(fat32_rename_file(src, dest) == 0) {
                console_print("Moved.\n");
            } else {
                console_print("Failed. (Source not found or destination exists).\n");
            }
        }
    }
    // CORRECT — format always writes plaintext; encryption is a post-format concern:
	else if (strcmp(command, "formatfs") == 0) {
		bool saved = g_fs_encryption_enabled;
		g_fs_encryption_enabled = false;   // format always writes raw
		fat32_format();
		g_fs_encryption_enabled = saved;
	}
    else if (strcmp(command, "chkdsk") == 0) {
        char* args_copy = new char[120];
        strncpy(args_copy, args, 119);
        args_copy[119] = '\0';
        
        bool fix = false;
        bool fullscan = false;
        
        if (strstr(args_copy, "/f") || strstr(args_copy, "/F")) {
            fix = true;
        }
        if (strstr(args_copy, "/r") || strstr(args_copy, "/R")) {
            fix = true;
            fullscan = true;
        }
        
        chkdsk(fix, true);
        
        if (fullscan) {
            chkdsk_full_scan(fix);
        }
        
        delete[] args_copy;
    }
    else if (strcmp(command, "time") == 0) { 
        RTC_Time t = read_rtc(); 
        char buf[64]; 
        snprintf(buf, 64, "%d:%d:%d %d/%d/%d\n", t.hour, t.minute, t.second, t.day, t.month, t.year); 
        console_print(buf); 
    }
    else if (strcmp(command, "version") == 0) { console_print("RTOS++ v1.0 - Robust Parsing\n"); }
    else if (strlen(command) > 0) { 
        console_print("Unknown command.\n"); 
    }
    
    if(!in_editor) print_prompt();
}
// ELF Loader implementation
int load_and_execute_elf(const char* filename, const char* args, TerminalWindow* terminal) {
    // Read ELF file from filesystem
    char* elf_data = fat32_read_file_as_string(filename);
    if (!elf_data) {
        if (terminal) {
            terminal->console_print("Failed to read ELF file: ");
            terminal->console_print(filename);
            terminal->console_print("\n");
        }
        return -1;
    }
    
    // Get file size by finding the entry and reading its size
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    if (fat32_find_entry(filename, &entry, &sector, &offset) != 0) {
        delete[] elf_data;
        return -1;
    }
    
    // Validate ELF header
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)elf_data;
    if (!validate_elf_header(ehdr)) {
        if (terminal) {
            terminal->console_print("Invalid ELF file\n");
        }
        delete[] elf_data;
        return -1;
    }
    
    // Find free process slot
    int slot = find_free_elf_slot();
    if (slot < 0) {
        if (terminal) {
            terminal->console_print("No free process slots\n");
        }
        delete[] elf_data;
        return -1;
    }
    
    ElfProcess* proc = &elf_processes[slot];
    
    // Calculate memory requirements
    uint32_t min_vaddr = 0xFFFFFFFF;
    uint32_t max_vaddr = 0;
    
    Elf32_Phdr* phdr = (Elf32_Phdr*)(elf_data + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint32_t seg_start = phdr[i].p_vaddr;
            uint32_t seg_end = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (seg_start < min_vaddr) min_vaddr = seg_start;
            if (seg_end > max_vaddr) max_vaddr = seg_end;
        }
    }
    
    // Allocate memory for process
    uint32_t memory_size = max_vaddr - min_vaddr + ELF_HEAP_SIZE;
    proc->memory_base = new uint8_t[memory_size];
    if (!proc->memory_base) {
        if (terminal) {
            terminal->console_print("Failed to allocate process memory\n");
        }
        delete[] elf_data;
        return -1;
    }
    memset(proc->memory_base, 0, memory_size);
    proc->memory_size = memory_size;
    
    // Load program segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint32_t vaddr = phdr[i].p_vaddr - min_vaddr;
            memcpy(proc->memory_base + vaddr, 
                   elf_data + phdr[i].p_offset, 
                   phdr[i].p_filesz);
            
            // Zero out BSS if memsz > filesz
            if (phdr[i].p_memsz > phdr[i].p_filesz) {
                memset(proc->memory_base + vaddr + phdr[i].p_filesz, 
                       0, 
                       phdr[i].p_memsz - phdr[i].p_filesz);
            }
        }
    }
    
    // Allocate stack
    proc->stack = new uint8_t[ELF_STACK_SIZE];
    if (!proc->stack) {
        delete[] proc->memory_base;
        delete[] elf_data;
        return -1;
    }
    memset(proc->stack, 0, ELF_STACK_SIZE);
    
    // Initialize process state
    proc->active = true;
    proc->entry_point = ehdr->e_entry - min_vaddr;
    proc->eip = proc->entry_point;
    proc->esp = ELF_STACK_SIZE - 16;
    proc->terminal = terminal;
    proc->waiting_for_input = false;
    proc->input_pos = 0;
    proc->completed = false;
    proc->exit_code = 0;
    
    // Copy command line
    if (args) {
        strncpy(proc->cmdline, args, 255);
        proc->cmdline[255] = '\0';
    } else {
        proc->cmdline[0] = '\0';
    }
    
    delete[] elf_data;
    
    if (terminal) {
        terminal->console_print("ELF process loaded (slot ");
        char buf[16];
        snprintf(buf, 16, "%d", slot);
        terminal->console_print(buf);
        terminal->console_print(")\n");
        // Tick ELF processes (add after VM ticks)

    }
    
    return slot;
}
    
    

public:
    TerminalWindow(int x, int y, const char* startup_command = nullptr) : Window(x, y, 640, 400, "Terminal"), line_count(0), line_pos(0), in_editor(false), 
        edit_lines(nullptr), edit_line_count(0), edit_current_line(0), edit_cursor_col(0), edit_scroll_offset(0),
        prompt_visual_lines(0) {
        memset(buffer, 0, sizeof(buffer));
        current_line[0] = '\0';
        startup_command_buffer[0] = '\0'; // Ensure buffer is empty by default

        if (startup_command) {
            // Save the command to be run on the first update cycle
            strncpy(startup_command_buffer, startup_command, 127);
        }
        
        update_prompt_display(); // Show the initial prompt
    }
    
    ~TerminalWindow() { 
        if(edit_lines) {
            for(int i = 0; i < edit_line_count; i++) delete[] edit_lines[i];
            delete[] edit_lines;
        }
    }

    void draw() override {
        if (!has_focus && is_closed) return;

        using namespace ColorPalette;
        
        uint32_t titlebar_color = has_focus ? TITLEBAR_ACTIVE : TITLEBAR_INACTIVE;
        draw_rect_filled(x, y, w, 25, titlebar_color);
        draw_string(title, x + 5, y + 8, TEXT_WHITE);

        draw_rect_filled(x + w - 22, y + 4, 18, 18, BUTTON_CLOSE);
        draw_string("X", x + w - 17, y + 8, TEXT_WHITE);

        draw_rect_filled(x, y + 25, w, h - 25, WINDOW_BG);

        for (int i = 0; i < w; i++) put_pixel_back(x + i, y, WINDOW_BORDER);
        for (int i = 0; i < w; i++) put_pixel_back(x + i, y + h - 1, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x, y + i, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x + w - 1, y + i, WINDOW_BORDER);

        if (!in_editor) {
    for (int i = 0; i < line_count && i < 38; i++) {
        draw_string(buffer[i], x + 5, y + 30 + i * 10, ColorPalette::TEXT_WHITE);
    }
} else {
    for (int row = 0; row < EDIT_ROWS; ++row) {
        int line_idx = edit_scroll_offset + row;
        int y_line = y + 30 + row * EDIT_LINE_PIX;

        if (line_idx < edit_line_count) {
            if (line_idx == edit_current_line) {
                draw_rect_filled(x + 2, y_line, w - 4, EDIT_LINE_PIX, ColorPalette::TEXT_GRAY);
            }
            draw_string(edit_lines[line_idx], x + 5, y_line, ColorPalette::TEXT_WHITE);
        }
    }

    if ((g_timer_ticks / 15) % 2 == 0 && edit_current_line >= edit_scroll_offset &&
        edit_current_line < edit_scroll_offset + EDIT_ROWS) {
        int visible_row = edit_current_line - edit_scroll_offset;
        int cursor_x = x + 5 + edit_cursor_col * EDIT_COL_PIX;
        int cursor_y = y + 30 + visible_row * EDIT_LINE_PIX;
        draw_rect_filled(cursor_x, cursor_y, EDIT_COL_PIX, EDIT_LINE_PIX, ColorPalette::CURSOR_WHITE);
    }
}
    }

    void on_key_press(char c) override {
    if (in_editor) {
        if (!edit_lines || edit_current_line >= edit_line_count) return;

        char* current_line_ptr = edit_lines[edit_current_line];
        size_t current_len = strlen(current_line_ptr);

        if (c == 17 || c == 27) { // Ctrl+Q or ESC to save and exit
            int total_len = 0;
            for (int i = 0; i < edit_line_count; i++) {
                total_len += strlen(edit_lines[i]) + 1;
            }
            char* file_content = new char[total_len + 1];
            if (!file_content) return;
            file_content[0] = '\0';
            for (int i = 0; i < edit_line_count; i++) {
                strcat(file_content, edit_lines[i]);
                if (i < edit_line_count - 1) {
                   strcat(file_content, "\n");
                }
            }
            fat32_write_file(edit_filename, file_content, strlen(file_content));
            delete[] file_content;
            in_editor = false;
            console_print("File saved.\n");
            return;
        } 
        else if (c == KEY_UP) {
            if (edit_current_line > 0) edit_current_line--;
        } 
        else if (c == KEY_DOWN) {
            if (edit_current_line < edit_line_count - 1) edit_current_line++;
        } 
        else if (c == KEY_LEFT) {
            if (edit_cursor_col > 0) edit_cursor_col--;
        } 
        else if (c == KEY_RIGHT) {
            if (edit_cursor_col < (int)current_len) edit_cursor_col++;
        } 
        else if (c == KEY_HOME) {
            edit_cursor_col = 0;
        }
        else if (c == KEY_END) {
            edit_cursor_col = current_len;
        }
        else if (c == KEY_DELETE) {
            if (edit_cursor_col < (int)current_len) {
                memmove(&current_line_ptr[edit_cursor_col], 
                       &current_line_ptr[edit_cursor_col + 1], 
                       current_len - edit_cursor_col);
            } else if (edit_current_line < edit_line_count - 1) {
                // Delete at end of line - join with next line
                char* next_line_ptr = edit_lines[edit_current_line + 1];
                if (current_len + strlen(next_line_ptr) < TERM_WIDTH - 1) {
                    strcat(current_line_ptr, next_line_ptr);
                    editor_delete_line_at(edit_current_line + 1);
                }
            }
        }
        else if (c == '\n') { // Enter key
            const char* right_part_text = &current_line_ptr[edit_cursor_col];
            editor_insert_line_at(edit_current_line + 1, right_part_text);
            current_line_ptr[edit_cursor_col] = '\0';
            edit_current_line++;
            edit_cursor_col = 0;
        } 
        else if (c == '\b') { // Backspace
            if (edit_cursor_col > 0) {
                memmove(&current_line_ptr[edit_cursor_col - 1], 
                       &current_line_ptr[edit_cursor_col], 
                       current_len - edit_cursor_col + 1);
                edit_cursor_col--;
            } else if (edit_current_line > 0) {
                int prev_line_idx = edit_current_line - 1;
                char* prev_line_ptr = edit_lines[prev_line_idx];
                int prev_len = strlen(prev_line_ptr);
                if (prev_len + current_len < TERM_WIDTH - 1) {
                    strcat(prev_line_ptr, current_line_ptr);
                    editor_delete_line_at(edit_current_line);
                    edit_current_line = prev_line_idx;
                    edit_cursor_col = prev_len;
                }
            }
        } 
        else if (c >= 32 && c < 127) { // Printable characters
            // **WORD WRAP IMPLEMENTATION**
            const int MAX_LINE_WIDTH = 75; // Characters before wrap
            
            if (current_len < TERM_WIDTH - 2) {
                // Insert character
                memmove(&current_line_ptr[edit_cursor_col + 1], 
                       &current_line_ptr[edit_cursor_col], 
                       current_len - edit_cursor_col + 1);
                current_line_ptr[edit_cursor_col] = c;
                edit_cursor_col++;
                
                // Check if line is too long and needs wrapping
                int new_len = strlen(current_line_ptr);
                if (new_len > MAX_LINE_WIDTH) {
                    // Find last space to wrap at
                    int wrap_pos = MAX_LINE_WIDTH;
                    bool found_space = false;
                    
                    for (int i = MAX_LINE_WIDTH; i > MAX_LINE_WIDTH - 20 && i > 0; i--) {
                        if (current_line_ptr[i] == ' ') {
                            wrap_pos = i;
                            found_space = true;
                            break;
                        }
                    }
                    
                    // If no space found near margin, force wrap at max width
                    if (!found_space) {
                        wrap_pos = MAX_LINE_WIDTH;
                    }
                    
                    // Create wrapped text for next line
                    char wrapped_text[TERM_WIDTH];
                    memset(wrapped_text, 0, TERM_WIDTH);
                    strcpy(wrapped_text, &current_line_ptr[wrap_pos]);
                    
                    // Trim leading space from wrapped text
                    char* trimmed = wrapped_text;
                    while (*trimmed == ' ') trimmed++;
                    
                    // Truncate current line at wrap point
                    current_line_ptr[wrap_pos] = '\0';
                    
                    // Insert wrapped text as new line
                    editor_insert_line_at(edit_current_line + 1, trimmed);
                    
                    // Move cursor to next line if it was past wrap point
                    if (edit_cursor_col > wrap_pos) {
                        edit_current_line++;
                        edit_cursor_col = edit_cursor_col - wrap_pos;
                        // Account for trimmed spaces
                        while (edit_cursor_col > 0 && wrapped_text[0] == ' ') {
                            edit_cursor_col--;
                        }
                        if (edit_cursor_col < 0) edit_cursor_col = 0;
                    }
                }
            }
        }
        
        editor_clamp_cursor_to_line();
        editor_ensure_cursor_visible();
        return; // END OF EDITOR HANDLING
    } else {
            if (c == '\n' && run_contexts[wm.get_focused_idx()].active) {
                prompt_visual_lines = 0;
                line_pos = 0;
                current_line[0] = '\0';
                update_prompt_display();
            } else if (c == '\n' && !run_contexts[wm.get_focused_idx()].active) {
                prompt_visual_lines = 0;
                handle_command();
                line_pos = 0;
                current_line[0] = '\0';
                update_prompt_display();
            }
			
			else if (c == '\b') {
                if (line_pos > 0) {
                    line_pos--;
                    current_line[line_pos] = 0;
                }
                update_prompt_display();
            } else if (c >= 32 && c < 127 && line_pos < TERM_WIDTH - 2) {
                current_line[line_pos++] = c;
                current_line[line_pos] = 0;
                update_prompt_display();
            }
        }
    }

     // --- THIS IS THE CORRECTED UPDATE METHOD ---
    void update() override {
        // Check if there is a startup command waiting to be executed
        if (startup_command_buffer[0] != '\0') {
            // Copy the command to the current line to be processed
            strncpy(current_line, startup_command_buffer, TERM_WIDTH - 1);
            
            // Clear the startup command so this only runs ONCE
            startup_command_buffer[0] = '\0'; 

            push_line(current_line);  // Display the command being run
            handle_command();         // Execute it
            
            // Reset the input line for the user
            line_pos = 0;
            current_line[0] = '\0';
            update_prompt_display();
        }
    }


    void console_print(const char* s) override {
        if (!s || in_editor) return;

        int saved_prompt_lines = prompt_visual_lines;
        if (saved_prompt_lines > 0) {
            remove_last_n_lines(saved_prompt_lines);
            prompt_visual_lines = 0;
        }

        push_wrapped_text(s, term_cols_cont());
        update_prompt_display();
    }
};
void WindowManager::execute_context_menu_action(int item_index) {
    if (item_index < 0 || item_index >= num_context_menu_items) return;
    const char* action = context_menu_items[item_index];

    if (current_context == CTX_DESKTOP) {
        if (strcmp(action, "File Explorer") == 0) {
            launch_new_explorer();
        } else if (strcmp(action, "Paste") == 0) {
            if (g_clipboard_buffer[0] != '\0') {
                const char* src_path = g_clipboard_buffer;
                const char* filename = strrchr(src_path, '/');
                filename = filename ? filename + 1 : src_path;
                
                char new_name[32] = "copy_of_";
                strncat(new_name, filename, 22);

                fat32_copy_file(src_path, new_name);
                load_desktop_items();
            }
        }
    }
    else if (current_context == CTX_ICON) {
        DesktopItem& item = desktop_items[context_icon_idx];
        
        if (strcmp(action, "Run") == 0) {
            char command_buffer[128];
            snprintf(command_buffer, 128, "run %s", item.name);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Edit") == 0) {
            char command_buffer[128];
            snprintf(command_buffer, 128, "edit \"%s\"", item.name);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Copy") == 0) {
            strncpy(g_clipboard_buffer, item.path, 1023);
        } else if (strcmp(action, "Delete") == 0) {
            fat32_remove_file(item.path);
            load_desktop_items();
        }
    }
    else if (current_context == CTX_EXPLORER_ITEM) {
        const char* filename = context_file_path;

        if (strcmp(action, "Run") == 0) {
            char command_buffer[128];
            snprintf(command_buffer, 128, "run %s", filename);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Edit") == 0) {
            char command_buffer[128];
            snprintf(command_buffer, 128, "edit \"%s\"", filename);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Create Shortcut") == 0) {
            char shortcut_name[32];
            char shortcut_content[128];
            
            strncpy(shortcut_name, filename, 27);
            char* dot = strrchr(shortcut_name, '.');
            if (dot) *dot = '\0';
            strcat(shortcut_name, ".lnk");

            snprintf(shortcut_content, 128, "run %s", filename);

            fat32_write_file(shortcut_name, shortcut_content, strlen(shortcut_content));
            load_desktop_items();
        } 
    }

    context_menu_active = false;
}

void WindowManager::handle_input(char key, int mx, int my, bool left_down, bool left_clicked, bool right_clicked) {
    // --- Static variables to track double-clicks ---
    static uint32_t last_click_tick = 0;
    static int last_click_icon_idx = -1;
    const uint32_t DOUBLE_CLICK_SPEED = 20; // Ticks to wait for a double click

    // --- 1. Handle Context Menu Clicks ---
    if (context_menu_active && left_clicked) {
        int menu_width = 150;
        int item_height = 20;
        if (mx > context_menu_x && mx < context_menu_x + menu_width) {
            int item_index = (my - context_menu_y) / item_height;
            if (item_index >= 0 && item_index < num_context_menu_items) {
                execute_context_menu_action(item_index);
                return; // Action taken, end input handling
            }
        }
        context_menu_active = false; // Clicked outside, close menu
    }

    if (context_menu_active && right_clicked) {
        context_menu_active = false;
        return;
    }

    // --- 2. Handle Dragging ---
    if (dragging_idx != -1) { // Dragging a window
        if (left_down) {
            windows[dragging_idx]->x = mx - drag_offset_x;
            windows[dragging_idx]->y = my - drag_offset_y;
        } else {
            dragging_idx = -1;
        }
        return;
    }
    if (dragging_icon_idx != -1) { // Dragging an icon
        if (left_down) {
            desktop_items[dragging_icon_idx].x = mx - drag_offset_x;
            desktop_items[dragging_icon_idx].y = my - drag_offset_y;
        } else {
            dragging_icon_idx = -1;
        }
        return;
    }
    
    // --- 3. Handle Right Clicks (Opening Context Menu) ---
    if (right_clicked) {
		if (focused_idx != -1) {
            Window* win = windows[focused_idx];
            if (mx >= win->x && mx < win->x + win->w && my >= win->y && my < win->y + win->h) {
                win->on_mouse_right_click(mx, my);
                return; // The window handled the click
            }
        }
        // First, check if a click happened on a desktop icon
        int clicked_icon_index = -1;
        for (int i = num_desktop_items - 1; i >= 0; --i) {
            if (mx >= desktop_items[i].x && mx < desktop_items[i].x + 40 &&
                my >= desktop_items[i].y && my < desktop_items[i].y + 50) {
                clicked_icon_index = i; // Save the index of the clicked icon
                break; // Found it, no need to check others
            }
        }

        if (clicked_icon_index != -1) {
            // A desktop icon was right-clicked
            context_menu_active = true;
            context_menu_x = mx;
            context_menu_y = my;
            current_context = CTX_ICON;
            context_icon_idx = clicked_icon_index; // Use the saved index
            num_context_menu_items = 0;

            // Check if it's an executable
            if (strstr(desktop_items[clicked_icon_index].name, ".obj") != nullptr || strstr(desktop_items[clicked_icon_index].name, ".OBJ") != nullptr) {
                context_menu_items[num_context_menu_items++] = "Run";
            }
            
            context_menu_items[num_context_menu_items++] = "Edit"; // ADDED THIS LINE
            context_menu_items[num_context_menu_items++] = "Copy";
            context_menu_items[num_context_menu_items++] = "Delete";

        } else {
            // No icon was clicked, this is a right-click on the desktop itself
            context_menu_active = true;
            context_menu_x = mx;
            context_menu_y = my;
            current_context = CTX_DESKTOP;
            num_context_menu_items = 0;
            context_menu_items[num_context_menu_items++] = "File Explorer";
            context_menu_items[num_context_menu_items++] = "Paste";
        }
        return;
    }

    // --- 4. Handle Left Clicks (Dragging, Opening, Focusing) ---
    if (left_clicked) {
        // Check window interactions first (top to bottom)
        for (int i = num_windows - 1; i >= 0; i--) {
            if (mx >= windows[i]->x && mx < windows[i]->x + windows[i]->w &&
                my >= windows[i]->y && my < windows[i]->y + windows[i]->h) {
                
                set_focus(i);
                if (windows[i]->is_in_close_button(mx, my)) {
                    windows[i]->close();
                } else if (windows[i]->is_in_titlebar(mx, my)) {
                    dragging_idx = focused_idx;
                    drag_offset_x = mx - windows[dragging_idx]->x;
                    drag_offset_y = my - windows[dragging_idx]->y;
                } else {
                    windows[i]->on_mouse_click(mx, my);
                }
                return;
            }
        }

        // Check icon interactions (double-click and drag start)
        for (int i = num_desktop_items - 1; i >= 0; --i) {
            if (mx >= desktop_items[i].x && mx < desktop_items[i].x + 32 &&
                my >= desktop_items[i].y && my < desktop_items[i].y + 45) {

                // Check for a double-click
                if (last_click_icon_idx == i && (g_timer_ticks - last_click_tick) < DOUBLE_CLICK_SPEED) {
                    // Double-click detected!
                    DesktopItem& item = desktop_items[i]; // Use a reference for cleaner code

					if (strcmp(item.path, "explorer.app") == 0) {
						launch_new_explorer();
					} 
					// This part handles executing .obj files
					else if (strstr(item.name, ".obj") != nullptr || strstr(item.name, ".OBJ") != nullptr) {
						char command_buffer[128];
						snprintf(command_buffer, 128, "run %s", item.name);
						launch_terminal_with_command(command_buffer);
					}
                    
                    // Reset double-click tracking
                    last_click_tick = 0;
                    last_click_icon_idx = -1;
                } else {
                    // This is a first click, start dragging and set up for double-click
                    dragging_icon_idx = i;
                    drag_offset_x = mx - desktop_items[i].x;
                    drag_offset_y = my - desktop_items[i].y;
                    last_click_icon_idx = i;
                    last_click_tick = g_timer_ticks;
                }
                return;
            }
        }

        // Check taskbar button clicks
        if (mx >= 5 && mx <= 80 && my >= (int)fb_info.height - 35 && my <= (int)fb_info.height - 5) {
            launch_new_terminal();
            return;
        }

        // If nothing was clicked, reset double-click tracking
        last_click_icon_idx = -1;
    }

    // --- 5. Handle Keyboard Input ---
    if (key != 0 && focused_idx != -1 && focused_idx < num_windows)
        windows[focused_idx]->on_key_press(key);
}

void WindowManager::print_to_focused(const char* s) {
    if (focused_idx != -1 && focused_idx < num_windows) 
        windows[focused_idx]->console_print(s);
}

void launch_new_terminal() {
    static int win_count = 0;
    int idx = (win_count++ % 10);
    int off = idx * 30;
    wm.add_window(new TerminalWindow(100 + off, 50 + off));
}


void launch_new_explorer() {
    static int win_count = 0;
    int idx = (win_count++ % 10);
    int off = idx * 30;
    wm.add_window(new FileExplorerWindow(120 + off, 70 + off, "/"));
}


// ADD THIS NEW FUNCTION
void launch_terminal_with_command(const char* command) {
    static int win_count = 0;
    int idx = (win_count++ % 10);
    int off = idx * 30;
    wm.add_window(new TerminalWindow(150 + off, 90 + off, command));
}

void swap_buffers() {
    if (fb_info.ptr && backbuffer) {
        uint32_t* dest = fb_info.ptr;
        uint32_t* src = backbuffer;
        size_t count = fb_info.width * fb_info.height;

        asm volatile (
            "rep movsl"
            : "=S"(src), "=D"(dest), "=c"(count)
            : "S"(src), "D"(dest), "c"(count)
            : "memory"
        );
    }
}

static volatile bool g_evt_timer = false;
static volatile bool g_evt_input = false;
static volatile bool g_evt_dirty = true;
// This is now defined before TerminalWindow to resolve the dependency
// static volatile uint32_t g_timer_ticks = 0;

extern "C" void idle_signal_timer() { g_evt_timer = true; g_timer_ticks++; }
extern "C" void idle_signal_input() { g_evt_input = true; }
extern "C" void mark_screen_dirty() { g_evt_dirty = true; }

static void init_screen_timer(uint16_t hz) {
    uint16_t divisor = 1193182 / hz;
    outb(0x43, 0x36);
    outb(0x40, divisor & 0xFF);
    outb(0x40, (divisor >> 8) & 0xFF);
}

// =============================================================================
// KERNEL MAIN - ATOMIC FRAME RENDERING
// =============================================================================

	
// =============================================================================
// INDEPENDENT RUN AND EXEC IMPLEMENTATION
// =============================================================================
// This refactoring completely decouples run and exec processes:
// - run: manages disk-based object files with full disk I/O context
// - exec: manages in-memory compiled code with no disk dependencies
// - Separate process tables, separate resource management
// - No shared state between the two subsystems

// =============================================================================
// SECTION 1: SEPARATE PROCESS CONTEXTS
// =============================================================================


// =============================================================================
// SECTION 2: INDEPENDENT INITIALIZATION
// =============================================================================

void init_run_subsystem() {
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        run_contexts[i].active = false;
        run_contexts[i].ahci_base = 0;
        run_contexts[i].port = 0;
        run_contexts[i].filename[0] = '\0';
    }
}

void init_exec_subsystem() {
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        exec_contexts[i].active = false;
        exec_contexts[i].exec_id = 0;
    }
}

// =============================================================================
// SECTION 3: RUN SUBSYSTEM (Disk-Based Execution)
// =============================================================================

// Find free run slot
static int allocate_run_slot() {
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (!run_contexts[i].active) {
            return i;
        }
    }
    return -1; // No free slots
}

// Load program from disk into run context
static int load_program_to_run_context(int slot, uint64_t ahci_base, int port, const char* filename) {
    RunContext* ctx = &run_contexts[slot];
    
    // Load object file from disk
    int result = TVMObject::load(ahci_base, port, filename, ctx->prog);
    if (result != 0) {
        return result;
    }
    
    // Store disk context
    ctx->ahci_base = ahci_base;
    ctx->port = port;
    strncpy(ctx->filename, filename, 63);
    ctx->filename[63] = '\0';
    
    return 0;
}

static void start_run_execution(int slot, int argc, const char* argv[], Window* win) {
    RunContext* ctx = &run_contexts[slot];
    ctx->vm.start_execution(ctx->prog, argc, argv, ctx->ahci_base, ctx->port, win);
    
    // â† ADD THIS LINE:
    ctx->vm.bound_window = win;
    
    ctx->active = true;
}

static void start_exec_execution(int slot, int argc, const char* argv[], Window* win) {
    ExecContext* ctx = &exec_contexts[slot];
    ctx->vm.start_execution(ctx->prog, argc, argv, 0, 0, win);
    
    // â† ADD THIS LINE:
    ctx->vm.bound_window = win;
    
    ctx->active = true;
}
// ── Drain any output the ELF process produced into its terminal ────────
static void flush_elf_output(int slot) {
    ElfProcess* proc = &elf_processes[slot];
    if (!proc->terminal || proc->out_empty()) return;

    // Collect into a small temp buffer for one console_print call
    char tmp[256];
    int  n = 0;
    while (!proc->out_empty() && n < 255) {
        tmp[n++] = proc->pop_output();
    }
    tmp[n] = '\0';
    if (n > 0) proc->terminal->console_print(tmp);
}

// ── Feed a character from the keyboard into a waiting ELF process ─────
void feed_elf_input(int slot, char c) {
    if (slot < 0 || slot >= MAX_ELF_PROCESSES) return;
    ElfProcess* proc = &elf_processes[slot];
    if (!proc->active || proc->completed) return;

    // Echo to terminal so the user sees what they typed
    if (proc->terminal) {
        char echo[2] = {c, 0};
        proc->terminal->console_print(echo);
    }

    if (c == '\n' || c == '\r') {
        // Terminate the line and mark ready
        proc->input_buffer[proc->input_pos] = '\0';
        proc->push_input('\n');          // signal end-of-line to process
        proc->waiting_for_input = false;
        proc->input_pos = 0;
    } else if (c == '\b') {
        if (proc->input_pos > 0) {
            proc->input_pos--;
            proc->input_buffer[proc->input_pos] = '\0';
        }
    } else if (proc->input_pos < 254) {
        proc->input_buffer[proc->input_pos++] = c;
        proc->push_input(c);
    }
}

bool elf_process_waiting_for_input() {
    for (int i = 0; i < MAX_ELF_PROCESSES; i++)
        if (elf_processes[i].active && elf_processes[i].waiting_for_input)
            return true;
    return false;
}
// =============================================================================
// x86 EMULATOR CORE - replaces the stub in tick_elf_processes()
// =============================================================================

struct X86State {
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi, esp, ebp;
    uint32_t eip;
    uint32_t eflags;
    bool initialized;
};
static X86State elf_cpu[MAX_ELF_PROCESSES];
void init_elf_subsystem() {
    for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
        elf_processes[i].active        = false;
        elf_processes[i].memory_base   = nullptr;
        elf_processes[i].stack         = nullptr;
        elf_processes[i].terminal      = nullptr;
        elf_processes[i].waiting_for_input = false;
        elf_processes[i].completed     = false;
        elf_processes[i].in_head  = elf_processes[i].in_tail  = 0;
        elf_processes[i].out_head = elf_processes[i].out_tail = 0;
		memset(&elf_cpu[i], 0, sizeof(X86State));
    }
}
// Flag helpers
#define FLAG_CF (1 << 0)
#define FLAG_ZF (1 << 6)
#define FLAG_SF (1 << 7)
#define FLAG_OF (1 << 11)

static void set_flags_add(X86State& cpu, uint32_t a, uint32_t b, uint32_t result) {
    cpu.eflags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF | FLAG_OF);
    if (result == 0) cpu.eflags |= FLAG_ZF;
    if (result & 0x80000000) cpu.eflags |= FLAG_SF;
    if (result < a) cpu.eflags |= FLAG_CF;
    if ((~(a ^ b) & (a ^ result)) & 0x80000000) cpu.eflags |= FLAG_OF;
}

static void set_flags_sub(X86State& cpu, uint32_t a, uint32_t b, uint32_t result) {
    cpu.eflags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF | FLAG_OF);
    if (result == 0) cpu.eflags |= FLAG_ZF;
    if (result & 0x80000000) cpu.eflags |= FLAG_SF;
    if (a < b) cpu.eflags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80000000) cpu.eflags |= FLAG_OF;
}

static void set_flags_logic(X86State& cpu, uint32_t result) {
    cpu.eflags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF | FLAG_OF);
    if (result == 0) cpu.eflags |= FLAG_ZF;
    if (result & 0x80000000) cpu.eflags |= FLAG_SF;
}

// Safe memory read from process address space
static bool elf_mem_read(ElfProcess* proc, uint32_t addr, void* out, uint32_t size) {
    // Check main memory
    if (addr + size <= proc->memory_size) {
        memcpy(out, proc->memory_base + addr, size);
        return true;
    }
    // Check stack (mapped above memory_size)
    uint32_t stack_base = 0x80000000;
    uint32_t stack_top  = stack_base + ELF_STACK_SIZE;
    if (addr >= stack_base && addr + size <= stack_top) {
        memcpy(out, proc->stack + (addr - stack_base), size);
        return true;
    }
    return false;
}

static bool elf_mem_write(ElfProcess* proc, uint32_t addr, const void* in, uint32_t size) {
    if (addr + size <= proc->memory_size) {
        memcpy(proc->memory_base + addr, in, size);
        return true;
    }
    uint32_t stack_base = 0x80000000;
    uint32_t stack_top  = stack_base + ELF_STACK_SIZE;
    if (addr >= stack_base && addr + size <= stack_top) {
        memcpy(proc->stack + (addr - stack_base), in, size);
        return true;
    }
    return false;
}

static uint8_t  elf_read8 (ElfProcess* p, uint32_t a) { uint8_t  v=0; elf_mem_read(p,a,&v,1); return v; }
static uint16_t elf_read16(ElfProcess* p, uint32_t a) { uint16_t v=0; elf_mem_read(p,a,&v,2); return v; }
static uint32_t elf_read32(ElfProcess* p, uint32_t a) { uint32_t v=0; elf_mem_read(p,a,&v,4); return v; }
static void elf_write8 (ElfProcess* p, uint32_t a, uint8_t  v) { elf_mem_write(p,a,&v,1); }
static void elf_write16(ElfProcess* p, uint32_t a, uint16_t v) { elf_mem_write(p,a,&v,2); }
static void elf_write32(ElfProcess* p, uint32_t a, uint32_t v) { elf_mem_write(p,a,&v,4); }

// Stack helpers
static void x86_push(ElfProcess* proc, X86State& cpu, uint32_t val) {
    cpu.esp -= 4;
    elf_write32(proc, cpu.esp, val);
}
static uint32_t x86_pop(ElfProcess* proc, X86State& cpu) {
    uint32_t val = elf_read32(proc, cpu.esp);
    cpu.esp += 4;
    return val;
}

// ModRM decoder - returns pointer to register or resolves memory address
static uint32_t decode_modrm(ElfProcess* proc, X86State& cpu,
                              uint8_t modrm, uint32_t* reg_out,
                              uint32_t** reg_ptr_out, bool is_write = false) {
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm  = modrm & 0x7;

    // Map reg field to register
    uint32_t* regs[8] = {
        &cpu.eax, &cpu.ecx, &cpu.edx, &cpu.ebx,
        &cpu.esp, &cpu.ebp, &cpu.esi, &cpu.edi
    };
    if (reg_out) *reg_out = reg;
    if (reg_ptr_out) *reg_ptr_out = regs[reg];

    if (mod == 3) {
        // Register operand - return the register value
        return *regs[rm];
    }

    // Memory operand - calculate effective address
    uint32_t ea = 0;
    bool has_sib = (rm == 4);
    bool has_disp8  = (mod == 1);
    bool has_disp32 = (mod == 2) || (mod == 0 && rm == 5);

    if (has_sib) {
        uint8_t sib = elf_read8(proc, cpu.eip++);
        uint8_t scale = (sib >> 6) & 0x3;
        uint8_t index = (sib >> 3) & 0x7;
        uint8_t base  = sib & 0x7;
        ea = *regs[base];
        if (index != 4) ea += *regs[index] << scale;
    } else if (mod == 0 && rm == 5) {
        ea = elf_read32(proc, cpu.eip); cpu.eip += 4;
    } else {
        ea = *regs[rm];
    }

    if (has_disp8)  { int8_t  d = (int8_t) elf_read8 (proc, cpu.eip++);    ea += d; }
    if (has_disp32) { int32_t d = (int32_t)elf_read32(proc, cpu.eip); cpu.eip += 4; ea += d; }

    return ea;
}

// Linux syscall handler
static bool handle_syscall(ElfProcess* proc, X86State& cpu) {
    uint32_t syscall_num = cpu.eax;

    switch (syscall_num) {
        case 1: // exit
            proc->exit_code = cpu.ebx;
            proc->completed = true;
            proc->active    = false;
            return false; // Signal: stop executing

        case 3: { // read
            // fd=ebx, buf=ecx, count=edx
            if (cpu.ebx == 0) { // stdin
                proc->waiting_for_input = true;
                // Will resume when input arrives via feed_elf_input()
                // For now store where to write
                cpu.eax = 0; // will be updated
            }
            break;
        }

        case 4: { // write
            // fd=ebx, buf=ecx, count=edx
            if (cpu.ebx == 1 || cpu.ebx == 2) { // stdout or stderr
                uint32_t buf_addr = cpu.ecx;
                uint32_t count    = cpu.edx;
                if (count > 4096) count = 4096; // safety cap
                char tmp[4097];
                uint32_t i = 0;
                for (; i < count; i++) {
                    uint8_t c = elf_read8(proc, buf_addr + i);
                    if (c == 0) break;
                    tmp[i] = (char)c;
                }
                tmp[i] = '\0';
                proc->push_output_str(tmp);
                cpu.eax = i;
            }
            break;
        }

        case 45: { // brk - simple bump allocator
            static uint32_t brk_ptr = 0;
            if (brk_ptr == 0) brk_ptr = proc->memory_size;
            if (cpu.ebx == 0) {
                cpu.eax = brk_ptr;
            } else {
                brk_ptr = cpu.ebx;
                cpu.eax = brk_ptr;
            }
            break;
        }

        case 20: // getpid
            cpu.eax = 1;
            break;

        case 6: // close - no-op
            cpu.eax = 0;
            break;

        default:
            // Unknown syscall - return -1 (ENOSYS)
            cpu.eax = (uint32_t)-38;
            break;
    }
    return true;
}

// Main x86 decode/execute - runs 'steps' instructions
// Returns false if process should stop
static bool x86_tick(int slot, int steps) {
    ElfProcess* proc = &elf_processes[slot];
    X86State&   cpu  = elf_cpu[slot];

    if (!proc->active || proc->completed) return false;
    if (proc->waiting_for_input) return true;

    // Initialize CPU state on first run
    if (!cpu.initialized) {
        cpu.eax = cpu.ebx = cpu.ecx = cpu.edx = 0;
        cpu.esi = cpu.edi = cpu.ebp = 0;
        cpu.eip    = proc->entry_point;
        cpu.esp    = 0x80000000 + ELF_STACK_SIZE - 16; // top of stack
        cpu.eflags = 0x202; // IF set
        cpu.initialized = true;

        // Push argc=0, argv=null onto stack (minimal startup)
        x86_push(proc, cpu, 0); // null envp
        x86_push(proc, cpu, 0); // null argv
        x86_push(proc, cpu, 0); // argc = 0
    }

    for (int step = 0; step < steps; step++) {
        if (proc->waiting_for_input || proc->completed) break;

        // Bounds check EIP
        if (cpu.eip >= proc->memory_size) {
            proc->completed = true;
            proc->active    = false;
            break;
        }

        uint8_t opcode = elf_read8(proc, cpu.eip++);

        // Handle prefixes
        bool prefix_66 = false; // operand size override
        while (opcode == 0x66) { prefix_66 = true; opcode = elf_read8(proc, cpu.eip++); }

        switch (opcode) {

            // --- MOV r32, imm32 ---
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                *regs[opcode - 0xB8] = elf_read32(proc, cpu.eip);
                cpu.eip += 4;
                break;
            }

            // --- MOV r8, imm8 ---
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
                uint8_t* regs8[8] = {
                    (uint8_t*)&cpu.eax,(uint8_t*)&cpu.ecx,
                    (uint8_t*)&cpu.edx,(uint8_t*)&cpu.ebx,
                    (uint8_t*)&cpu.eax+1,(uint8_t*)&cpu.ecx+1,
                    (uint8_t*)&cpu.edx+1,(uint8_t*)&cpu.ebx+1
                };
                *regs8[opcode - 0xB0] = elf_read8(proc, cpu.eip++);
                break;
            }

            // --- MOV r/m32, r32 (89) ---
            case 0x89: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint32_t reg_idx; uint32_t* reg_ptr;
                uint32_t ea = decode_modrm(proc, cpu, modrm, &reg_idx, &reg_ptr);
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    *regs[ea] = *reg_ptr; // reg to reg (ea is actually rm reg index here)
                    // Recalculate: ea returned *value* of rm reg; we need rm index
                    uint8_t rm = modrm & 7;
                    *regs[rm] = *reg_ptr;
                } else {
                    elf_write32(proc, ea, *reg_ptr);
                }
                break;
            }

            // --- MOV r32, r/m32 (8B) ---
            case 0x8B: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if (mod == 3) {
                    *regs[reg] = *regs[rm];
                } else {
                    uint32_t reg_idx; uint32_t* rp;
                    uint32_t ea = decode_modrm(proc, cpu, modrm, &reg_idx, &rp);
                    *regs[reg] = elf_read32(proc, ea);
                }
                break;
            }

            // --- MOV [r/m32], imm32 (C7 /0) ---
            case 0xC7: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint32_t reg_idx; uint32_t* rp;
                uint32_t ea = decode_modrm(proc, cpu, modrm, &reg_idx, &rp);
                uint32_t imm = elf_read32(proc, cpu.eip); cpu.eip += 4;
                if ((modrm >> 6) == 3) {
                    uint32_t* regs[8] = {
                        &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                        &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                    };
                    *regs[modrm & 7] = imm;
                } else {
                    elf_write32(proc, ea, imm);
                }
                break;
            }

            // --- PUSH r32 ---
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57: {
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                x86_push(proc, cpu, *regs[opcode - 0x50]);
                break;
            }

            // --- POP r32 ---
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                *regs[opcode - 0x58] = x86_pop(proc, cpu);
                break;
            }

            // --- PUSH imm32 ---
            case 0x68: {
                uint32_t imm = elf_read32(proc, cpu.eip); cpu.eip += 4;
                x86_push(proc, cpu, imm);
                break;
            }

            // --- PUSH imm8 (sign extended) ---
            case 0x6A: {
                int8_t imm = (int8_t)elf_read8(proc, cpu.eip++);
                x86_push(proc, cpu, (int32_t)imm);
                break;
            }

            // --- ADD r/m32, imm8 (sign extended) / imm32 (83 /0, 81 /0) ---
            case 0x83: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t op = (modrm >> 3) & 7;
                uint8_t rm = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                int32_t imm = (int8_t)elf_read8(proc, cpu.eip++);

                uint32_t reg_idx; uint32_t* rp;
                uint32_t ea = 0;
                uint32_t* target = nullptr;
                uint32_t mem_val = 0;

                if ((modrm >> 6) == 3) {
                    target = regs[rm];
                } else {
                    ea = decode_modrm(proc, cpu, modrm, &reg_idx, &rp);
                    mem_val = elf_read32(proc, ea);
                    target = &mem_val;
                }

                uint32_t a = *target;
                uint32_t result;
                switch (op) {
                    case 0: result = a + (uint32_t)imm; set_flags_add(cpu, a, (uint32_t)imm, result); *target = result; break; // ADD
                    case 1: result = a | (uint32_t)imm; set_flags_logic(cpu, result); *target = result; break; // OR
                    case 4: result = a & (uint32_t)imm; set_flags_logic(cpu, result); *target = result; break; // AND
                    case 5: result = a - (uint32_t)imm; set_flags_sub(cpu, a, (uint32_t)imm, result); *target = result; break; // SUB
                    case 6: result = a ^ (uint32_t)imm; set_flags_logic(cpu, result); *target = result; break; // XOR
                    case 7: result = a - (uint32_t)imm; set_flags_sub(cpu, a, (uint32_t)imm, result); break; // CMP (no store)
                    default: break;
                }
                if ((modrm >> 6) != 3 && op != 7) elf_write32(proc, ea, *target);
                break;
            }

            // --- ADD eax, imm32 ---
            case 0x05: {
                uint32_t imm = elf_read32(proc, cpu.eip); cpu.eip += 4;
                uint32_t result = cpu.eax + imm;
                set_flags_add(cpu, cpu.eax, imm, result);
                cpu.eax = result;
                break;
            }

            // --- ADD r/m32, r32 ---
            case 0x01: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if (mod == 3) {
                    uint32_t result = *regs[rm] + *regs[reg];
                    set_flags_add(cpu, *regs[rm], *regs[reg], result);
                    *regs[rm] = result;
                } else {
                    uint32_t ridx; uint32_t* rp;
                    uint32_t ea = decode_modrm(proc, cpu, modrm, &ridx, &rp);
                    uint32_t val = elf_read32(proc, ea);
                    uint32_t result = val + *regs[reg];
                    set_flags_add(cpu, val, *regs[reg], result);
                    elf_write32(proc, ea, result);
                }
                break;
            }

            // --- SUB r/m32, r32 (29) ---
            case 0x29: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if (mod == 3) {
                    uint32_t result = *regs[rm] - *regs[reg];
                    set_flags_sub(cpu, *regs[rm], *regs[reg], result);
                    *regs[rm] = result;
                }
                break;
            }

            // --- SUB eax, imm32 ---
            case 0x2D: {
                uint32_t imm = elf_read32(proc, cpu.eip); cpu.eip += 4;
                uint32_t result = cpu.eax - imm;
                set_flags_sub(cpu, cpu.eax, imm, result);
                cpu.eax = result;
                break;
            }

            // --- XOR r/m32, r32 (31) ---
            case 0x31: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    *regs[rm] ^= *regs[reg];
                    set_flags_logic(cpu, *regs[rm]);
                }
                break;
            }

            // --- XOR r32, r/m32 (33) ---
            case 0x33: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    *regs[reg] ^= *regs[rm];
                    set_flags_logic(cpu, *regs[reg]);
                }
                break;
            }

            // --- AND r/m32, r32 (21) ---
            case 0x21: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    *regs[rm] &= *regs[reg];
                    set_flags_logic(cpu, *regs[rm]);
                }
                break;
            }

            // --- CMP r/m32, r32 (39) ---
            case 0x39: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    uint32_t result = *regs[rm] - *regs[reg];
                    set_flags_sub(cpu, *regs[rm], *regs[reg], result);
                }
                break;
            }

            // --- CMP r32, r/m32 (3B) ---
            case 0x3B: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    uint32_t result = *regs[reg] - *regs[rm];
                    set_flags_sub(cpu, *regs[reg], *regs[rm], result);
                }
                break;
            }

            // --- CMP eax, imm32 (3D) ---
            case 0x3D: {
                uint32_t imm = elf_read32(proc, cpu.eip); cpu.eip += 4;
                uint32_t result = cpu.eax - imm;
                set_flags_sub(cpu, cpu.eax, imm, result);
                break;
            }

            // --- TEST r/m32, r32 (85) ---
            case 0x85: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    set_flags_logic(cpu, *regs[rm] & *regs[reg]);
                }
                break;
            }

            // --- INC r32 (40-47) ---
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47: {
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                uint32_t* r = regs[opcode - 0x40];
                uint32_t old = *r;
                (*r)++;
                // INC doesn't affect CF
                uint32_t saved_cf = cpu.eflags & FLAG_CF;
                set_flags_add(cpu, old, 1, *r);
                cpu.eflags = (cpu.eflags & ~FLAG_CF) | saved_cf;
                break;
            }

            // --- DEC r32 (48-4F) ---
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                uint32_t* r = regs[opcode - 0x48];
                uint32_t old = *r;
                (*r)--;
                uint32_t saved_cf = cpu.eflags & FLAG_CF;
                set_flags_sub(cpu, old, 1, *r);
                cpu.eflags = (cpu.eflags & ~FLAG_CF) | saved_cf;
                break;
            }

            // --- JMP rel8 (EB) ---
            case 0xEB: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                cpu.eip += rel;
                break;
            }

            // --- JMP rel32 (E9) ---
            case 0xE9: {
                int32_t rel = (int32_t)elf_read32(proc, cpu.eip); cpu.eip += 4;
                cpu.eip += rel;
                break;
            }

            // --- JE/JZ rel8 (74) ---
            case 0x74: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                if (cpu.eflags & FLAG_ZF) cpu.eip += rel;
                break;
            }

            // --- JNE/JNZ rel8 (75) ---
            case 0x75: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                if (!(cpu.eflags & FLAG_ZF)) cpu.eip += rel;
                break;
            }

            // --- JL rel8 (7C) ---
            case 0x7C: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                bool sf = (cpu.eflags & FLAG_SF) != 0;
                bool of = (cpu.eflags & FLAG_OF) != 0;
                if (sf != of) cpu.eip += rel;
                break;
            }

            // --- JLE rel8 (7E) ---
            case 0x7E: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                bool zf = (cpu.eflags & FLAG_ZF) != 0;
                bool sf = (cpu.eflags & FLAG_SF) != 0;
                bool of = (cpu.eflags & FLAG_OF) != 0;
                if (zf || (sf != of)) cpu.eip += rel;
                break;
            }

            // --- JG rel8 (7F) ---
            case 0x7F: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                bool zf = (cpu.eflags & FLAG_ZF) != 0;
                bool sf = (cpu.eflags & FLAG_SF) != 0;
                bool of = (cpu.eflags & FLAG_OF) != 0;
                if (!zf && (sf == of)) cpu.eip += rel;
                break;
            }

            // --- JGE rel8 (7D) ---
            case 0x7D: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                bool sf = (cpu.eflags & FLAG_SF) != 0;
                bool of = (cpu.eflags & FLAG_OF) != 0;
                if (sf == of) cpu.eip += rel;
                break;
            }

            // --- JA rel8 (77) - Jump if above (CF=0 and ZF=0) ---
            case 0x77: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                if (!(cpu.eflags & FLAG_CF) && !(cpu.eflags & FLAG_ZF)) cpu.eip += rel;
                break;
            }

            // --- JB rel8 (72) - Jump if below (CF=1) ---
            case 0x72: {
                int8_t rel = (int8_t)elf_read8(proc, cpu.eip++);
                if (cpu.eflags & FLAG_CF) cpu.eip += rel;
                break;
            }

            // --- 0F prefix (two-byte opcodes) ---
            case 0x0F: {
                uint8_t op2 = elf_read8(proc, cpu.eip++);
                switch (op2) {
                    // JE/JZ rel32
                    case 0x84: { int32_t rel = (int32_t)elf_read32(proc,cpu.eip); cpu.eip+=4; if(cpu.eflags&FLAG_ZF) cpu.eip+=rel; break; }
                    // JNE/JNZ rel32
                    case 0x85: { int32_t rel = (int32_t)elf_read32(proc,cpu.eip); cpu.eip+=4; if(!(cpu.eflags&FLAG_ZF)) cpu.eip+=rel; break; }
                    // JL rel32
                    case 0x8C: { int32_t rel=(int32_t)elf_read32(proc,cpu.eip); cpu.eip+=4; bool sf=(cpu.eflags&FLAG_SF)!=0,of=(cpu.eflags&FLAG_OF)!=0; if(sf!=of) cpu.eip+=rel; break; }
                    // JGE rel32
                    case 0x8D: { int32_t rel=(int32_t)elf_read32(proc,cpu.eip); cpu.eip+=4; bool sf=(cpu.eflags&FLAG_SF)!=0,of=(cpu.eflags&FLAG_OF)!=0; if(sf==of) cpu.eip+=rel; break; }
                    // JLE rel32
                    case 0x8E: { int32_t rel=(int32_t)elf_read32(proc,cpu.eip); cpu.eip+=4; bool zf=(cpu.eflags&FLAG_ZF)!=0,sf=(cpu.eflags&FLAG_SF)!=0,of=(cpu.eflags&FLAG_OF)!=0; if(zf||(sf!=of)) cpu.eip+=rel; break; }
                    // JG rel32
                    case 0x8F: { int32_t rel=(int32_t)elf_read32(proc,cpu.eip); cpu.eip+=4; bool zf=(cpu.eflags&FLAG_ZF)!=0,sf=(cpu.eflags&FLAG_SF)!=0,of=(cpu.eflags&FLAG_OF)!=0; if(!zf&&(sf==of)) cpu.eip+=rel; break; }
                    // MOVZX r32, r/m8
                    case 0xB6: {
                        uint8_t modrm = elf_read8(proc, cpu.eip++);
                        uint8_t reg = (modrm >> 3) & 7;
                        uint8_t rm  = modrm & 7;
                        uint32_t* regs[8] = {
                            &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                            &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                        };
                        if ((modrm >> 6) == 3) {
                            *regs[reg] = (uint8_t)(*regs[rm] & 0xFF);
                        } else {
                            uint32_t ridx; uint32_t* rp;
                            uint32_t ea = decode_modrm(proc, cpu, modrm, &ridx, &rp);
                            *regs[reg] = elf_read8(proc, ea);
                        }
                        break;
                    }
                    // IMUL r32, r/m32, imm8
                    case 0xAF: {
                        uint8_t modrm = elf_read8(proc, cpu.eip++);
                        uint8_t reg = (modrm >> 3) & 7;
                        uint8_t rm  = modrm & 7;
                        uint32_t* regs[8] = {
                            &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                            &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                        };
                        if ((modrm >> 6) == 3) {
                            *regs[reg] = (int32_t)*regs[reg] * (int32_t)*regs[rm];
                        }
                        break;
                    }
                    default:
                        // Unknown two-byte opcode - skip
                        break;
                }
                break;
            }

            // --- CALL rel32 (E8) ---
            case 0xE8: {
                int32_t rel = (int32_t)elf_read32(proc, cpu.eip); cpu.eip += 4;
                x86_push(proc, cpu, cpu.eip);
                cpu.eip += rel;
                break;
            }

            // --- RET (C3) ---
            case 0xC3: {
                cpu.eip = x86_pop(proc, cpu);
                break;
            }

            // --- RET imm16 (C2) ---
            case 0xC2: {
                uint16_t imm = elf_read16(proc, cpu.eip); cpu.eip += 2;
                cpu.eip = x86_pop(proc, cpu);
                cpu.esp += imm;
                break;
            }

            // --- LEAVE (C9) ---
            case 0xC9: {
                cpu.esp = cpu.ebp;
                cpu.ebp = x86_pop(proc, cpu);
                break;
            }

            // --- NOP (90) ---
            case 0x90:
                break;

            // --- INT (CD) ---
            case 0xCD: {
                uint8_t int_num = elf_read8(proc, cpu.eip++);
                if (int_num == 0x80) {
                    if (!handle_syscall(proc, cpu)) return false;
                }
                break;
            }

            // --- LEA r32, m (8D) ---
            case 0x8D: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                uint32_t ridx; uint32_t* rp;
                uint32_t ea = decode_modrm(proc, cpu, modrm, &ridx, &rp);
                *regs[reg] = ea;
                break;
            }

            // --- MOV r/m8, imm8 (C6) ---
            case 0xC6: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t imm = elf_read8(proc, cpu.eip++);
                if ((modrm >> 6) == 3) {
                    // Register - write low byte
                    uint32_t* regs[8] = {
                        &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                        &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                    };
                    *((uint8_t*)regs[modrm & 7]) = imm;
                } else {
                    uint32_t ridx; uint32_t* rp;
                    uint32_t ea = decode_modrm(proc, cpu, modrm, &ridx, &rp);
                    elf_write8(proc, ea, imm);
                }
                break;
            }

            // --- MOV r/m8, r8 (88) ---
            case 0x88: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                uint8_t val = (uint8_t)(*regs[reg] & 0xFF);
                if ((modrm >> 6) == 3) {
                    *((uint8_t*)regs[modrm & 7]) = val;
                } else {
                    uint32_t ridx; uint32_t* rp;
                    uint32_t ea = decode_modrm(proc, cpu, modrm, &ridx, &rp);
                    elf_write8(proc, ea, val);
                }
                break;
            }

            // --- MOV r8, r/m8 (8A) ---
            case 0x8A: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    *regs[reg] = (*regs[reg] & 0xFFFFFF00) |
                                 (*regs[modrm & 7] & 0xFF);
                } else {
                    uint32_t ridx; uint32_t* rp;
                    uint32_t ea = decode_modrm(proc, cpu, modrm, &ridx, &rp);
                    *regs[reg] = (*regs[reg] & 0xFFFFFF00) | elf_read8(proc, ea);
                }
                break;
            }

            // --- IMUL r32, r/m32, imm8 (6B) ---
            case 0x6B: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm  = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                int8_t imm = (int8_t)elf_read8(proc, cpu.eip++);
                if ((modrm >> 6) == 3) {
                    *regs[reg] = (int32_t)*regs[rm] * (int32_t)imm;
                }
                break;
            }

            // --- SHL / SHR / SAR r/m32, imm8 (C1) ---
            case 0xC1: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t op = (modrm >> 3) & 7;
                uint8_t rm = modrm & 7;
                uint8_t count = elf_read8(proc, cpu.eip++) & 31;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                if ((modrm >> 6) == 3) {
                    switch (op) {
                        case 4: *regs[rm] <<= count; break; // SHL
                        case 5: *regs[rm] >>= count; break; // SHR
                        case 7: *regs[rm] = (uint32_t)((int32_t)*regs[rm] >> count); break; // SAR
                    }
                    set_flags_logic(cpu, *regs[rm]);
                }
                break;
            }

            // --- MUL eax, r/m32 (F7 /4) ---
            // --- DIV eax, r/m32 (F7 /6) ---
            // --- NEG r/m32 (F7 /3) ---
            case 0xF7: {
                uint8_t modrm = elf_read8(proc, cpu.eip++);
                uint8_t op = (modrm >> 3) & 7;
                uint8_t rm = modrm & 7;
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                uint32_t val = ((modrm >> 6) == 3) ? *regs[rm] : elf_read32(proc, decode_modrm(proc, cpu, modrm, nullptr, nullptr));
                switch (op) {
                    case 2: { // NOT
                        if ((modrm >> 6) == 3) *regs[rm] = ~val;
                        break;
                    }
                    case 3: { // NEG
                        if ((modrm >> 6) == 3) { *regs[rm] = (uint32_t)(-(int32_t)val); set_flags_logic(cpu, *regs[rm]); }
                        break;
                    }
                    case 4: { // MUL  — unsigned
						uint64_t result = (uint64_t)cpu.eax * (uint64_t)val;
						cpu.eax = (uint32_t)(result & 0xFFFFFFFF);
						cpu.edx = (uint32_t)(result >> 32);
						break;
					}
					case 5: { // IMUL — signed, needs int64_t
						int64_t result = (int64_t)(int32_t)cpu.eax * (int64_t)(int32_t)val;
						cpu.eax = (uint32_t)((uint64_t)result & 0xFFFFFFFF);
						cpu.edx = (uint32_t)((uint64_t)result >> 32);
						break;
					}
					case 6: { // DIV  — unsigned
						if (val == 0) { proc->completed = true; proc->active = false; break; }
						uint64_t dividend = ((uint64_t)cpu.edx << 32) | cpu.eax;
						cpu.eax = (uint32_t)(dividend / val);
						cpu.edx = (uint32_t)(dividend % val);
						break;
					}
					case 7: { // IDIV — signed
						if (val == 0) { proc->completed = true; proc->active = false; break; }
						int64_t dividend = ((int64_t)(int32_t)cpu.edx << 32) | (uint64_t)cpu.eax;
						cpu.eax = (uint32_t)((int32_t)(dividend / (int32_t)val));
						cpu.edx = (uint32_t)((int32_t)(dividend % (int32_t)val));
						break;
					}
                }
                break;
            }

            // --- XCHG eax, r32 (91-97) ---
            case 0x91: case 0x92: case 0x93: case 0x94:
            case 0x95: case 0x96: case 0x97: {
                uint32_t* regs[8] = {
                    &cpu.eax,&cpu.ecx,&cpu.edx,&cpu.ebx,
                    &cpu.esp,&cpu.ebp,&cpu.esi,&cpu.edi
                };
                uint32_t tmp = cpu.eax;
                cpu.eax = *regs[opcode - 0x90];
                *regs[opcode - 0x90] = tmp;
                break;
            }

            // --- PUSHA (60) ---
            case 0x60: {
                uint32_t old_esp = cpu.esp;
                x86_push(proc, cpu, cpu.eax);
                x86_push(proc, cpu, cpu.ecx);
                x86_push(proc, cpu, cpu.edx);
                x86_push(proc, cpu, cpu.ebx);
                x86_push(proc, cpu, old_esp);
                x86_push(proc, cpu, cpu.ebp);
                x86_push(proc, cpu, cpu.esi);
                x86_push(proc, cpu, cpu.edi);
                break;
            }

            // --- POPA (61) ---
            case 0x61: {
                cpu.edi = x86_pop(proc, cpu);
                cpu.esi = x86_pop(proc, cpu);
                cpu.ebp = x86_pop(proc, cpu);
                x86_pop(proc, cpu); // skip esp
                cpu.ebx = x86_pop(proc, cpu);
                cpu.edx = x86_pop(proc, cpu);
                cpu.ecx = x86_pop(proc, cpu);
                cpu.eax = x86_pop(proc, cpu);
                break;
            }

            // --- CLD (FC) / STD (FD) --- ignore direction flag
            case 0xFC: case 0xFD:
                break;

            // --- HLT (F4) ---
            case 0xF4: {
                proc->completed = true;
                proc->active    = false;
                return false;
            }

            default: {
                // Unknown opcode - log and halt process
                char msg[64];
                snprintf(msg, 64, "[ELF] unknown opcode 0x%02x at eip=0x%x\n",
                         opcode, cpu.eip - 1);
                proc->push_output_str(msg);
                proc->completed = true;
                proc->active    = false;
                return false;
            }
        }
    }

    return !proc->completed;
}

// =============================================================================
// REPLACE tick_elf_processes() with this:
// =============================================================================
void tick_elf_processes() {
    for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
        ElfProcess* proc = &elf_processes[i];
        if (!proc->active || proc->completed) continue;

        if (proc->waiting_for_input) {
            flush_elf_output(i);
            continue;
        }

        // Run 200 instructions per tick
        bool still_running = x86_tick(i, 200);

        // Drain output to terminal every tick
        flush_elf_output(i);

        if (!still_running) {
            proc->active = false;
            if (proc->terminal) {
                char msg[64];
                snprintf(msg, 64, "[ELF slot %d] exited (code %d)\n",
                         i, proc->exit_code);
                proc->terminal->console_print(msg);
            }
        }
    }
}

void tick_run_processes(int steps_per_process) {
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (run_contexts[i].active) {
            // Check FIRST if waiting for input - don't call tick yet
            if (run_contexts[i].vm.waiting_for_input) {
                continue;  // Skip this process, it's paused waiting
            }
            
            int still_running = run_contexts[i].vm.tick(steps_per_process);
            
            // Only deactivate if process is truly done (not waiting)
            if (!still_running && !run_contexts[i].vm.waiting_for_input) {
                run_contexts[i].active = false;
                char msg[128];
                snprintf(msg, 128, "RUN process exited with code: %d\n", 
                        run_contexts[i].vm.exit_code);
                wm.print_to_focused(msg);
            }
        }
    }
}


// Feed input to run process
void feed_run_input(int slot, char c) {
    if (slot >= 0 && slot < MAX_RUN_PROCESSES && run_contexts[slot].active) {
        run_contexts[slot].vm.feed_input(c);
    }
}

// Check if any run process is waiting for input

// =============================================================================
// SECTION 4: EXEC SUBSYSTEM (Memory-Based Execution)
// =============================================================================

// Find free exec slot
static int allocate_exec_slot() {
    static int next_exec_id = 1;
    
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        if (!exec_contexts[i].active) {
            exec_contexts[i].exec_id = next_exec_id++;
            return i;
        }
    }
    return -1; // No free slots
}

// Compile and load program into exec context
static int compile_to_exec_context(int slot, const char* code_text) {
    ExecContext* ctx = &exec_contexts[slot];
    
    // Compile source code in memory
    TCompiler C;
    int result = C.compile(code_text);
    if (result != 0) {
        return -1; // Compilation failed
    }
    
    // Copy compiled program to context
    ctx->prog = C.pr;
    
    return 0;
}
void tick_exec_processes(int steps_per_process) {
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        if (exec_contexts[i].active) {
            // Check FIRST if waiting for input
            if (exec_contexts[i].vm.waiting_for_input) {
                continue;  // Skip, paused waiting
            }
            
            int still_running = exec_contexts[i].vm.tick(steps_per_process);
            
            // Only deactivate if truly done AND not waiting
            if (!still_running && !exec_contexts[i].vm.waiting_for_input) {
                exec_contexts[i].active = false;
                char msg[128];
                snprintf(msg, 128, "EXEC process exited with code: %d\n", 
                        exec_contexts[i].vm.exit_code);
                wm.print_to_focused(msg);
            }
        }
    }
}

// Feed input to exec process
void feed_exec_input(int slot, char c) {
    if (slot >= 0 && slot < MAX_EXEC_PROCESSES && exec_contexts[slot].active) {
        exec_contexts[slot].vm.feed_input(c);
    }
}

// Check if any exec process is waiting for input
bool exec_process_waiting_for_input() {
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        if (exec_contexts[i].active && exec_contexts[i].vm.waiting_for_input) {
            return true;
        }
    }
    return false;
}

// =============================================================================
// SECTION 5: INDEPENDENT COMMAND HANDLERS
// =============================================================================

// RUN command - completely independent, only uses RunContext
extern "C" void cmd_run(uint64_t ahci_base, int port, const char* filename) {
    // 1. Allocate run slot
    int slot = allocate_run_slot();
    if (slot == -1) {
        wm.print_to_focused("Error: Max RUN processes reached.\n");
        return;
    }
    
    // 2. Load program from disk
    int load_result = load_program_to_run_context(slot, ahci_base, port, filename);
    if (load_result != 0) {
        wm.print_to_focused("Error: Failed to load object file.\n");
        return;
    }
    
    // 3. Get window for output
    Window* win = wm.get_window(wm.get_focused_idx());
    
    // 4. Start execution with disk context
    static const char* argv[] = {filename};
    start_run_execution(slot, 1, argv, win);
    
    // 5. Report success
    if (win) {
        char msg[128];
        snprintf(msg, 128, "RUN: Started '%s' in slot %d\n", filename, slot);
        win->console_print(msg);
    }
}

// EXEC command - completely independent, only uses ExecContext
extern "C" void cmd_exec(const char* code_text) {
    // 1. Allocate exec slot
    int slot = allocate_exec_slot();
    if (slot == -1) {
        wm.print_to_focused("Error: Max EXEC processes reached.\n");
        return;
    }
    
    // 2. Compile code in memory
    int compile_result = compile_to_exec_context(slot, code_text);
    if (compile_result != 0) {
        wm.print_to_focused("Error: Compilation failed.\n");
        return;
    }
    
    // 3. Get window for output
    Window* win = wm.get_window(wm.get_focused_idx());
    
    // 4. Start execution without disk context
    static const char* argv[] = {"<inline>"};
    start_exec_execution(slot, 1, argv, win);
    
    // 5. Report success
    if (win) {
        char msg[128];
        snprintf(msg, 128, "EXEC: Started inline code in slot %d (id=%d)\n", 
                 slot, exec_contexts[slot].exec_id);
        win->console_print(msg);
    }
}

// =============================================================================
// SECTION 6: MAIN LOOP INTEGRATION
// =============================================================================

void handle_vm_input(char c) {
    // Feed to all waiting run processes
    if (run_process_waiting_for_input()) {
        for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
            if (run_contexts[i].active && run_contexts[i].vm.waiting_for_input) {
                feed_run_input(i, c);
            }
        }
    }
    
    // Feed to all waiting exec processes
    if (exec_process_waiting_for_input()) {
        for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
            if (exec_contexts[i].active && exec_contexts[i].vm.waiting_for_input) {
                feed_exec_input(i, c);
            }
        }
    }
}

// =============================================================================
// SECTION 7: INITIALIZATION (Call from kernel_main)
// =============================================================================

void initialize_vm_subsystems() {
    init_run_subsystem();
    init_exec_subsystem();
}

// =============================================================================
// SECTION 8: OPTIONAL MANAGEMENT FUNCTIONS
// =============================================================================



// =============================================================================
// IMPLEMENTATION NOTES:
// =============================================================================
/*
KEY BENEFITS OF THIS REFACTORING:

1. COMPLETE INDEPENDENCE
   - run and exec have their own process tables
   - No shared state between subsystems
   - Can be developed/debugged independently

2. SEPARATE RESOURCE MANAGEMENT
   - run manages disk I/O resources (ahci_base, port)
   - exec manages memory resources only
   - Different lifecycle management

3. DIFFERENT EXECUTION CONTEXTS
   - run: Full disk access, can load files during execution
   - exec: No disk access, pure in-memory execution
   - Clear separation of capabilities

4. SCALABILITY
   - Can easily increase MAX_RUN_PROCESSES independently of MAX_EXEC_PROCESSES
   - Can add different tick rates for each subsystem
   - Can prioritize one over the other

5. DEBUGGING
   - Easier to trace issues (separate process lists)
   - Can disable one subsystem without affecting the other
   - Clear ownership of resources

6. FUTURE EXTENSIONS
   - Easy to add run-specific features (disk caching, persistent processes)
   - Easy to add exec-specific features (JIT compilation, sandboxing)
   - Can add inter-process communication within each subsystem

USAGE EXAMPLE:


In terminal command handler:
   

MIGRATION PATH:

1. Add the new context structures above your current code
2. Implement init_run_subsystem() and init_exec_subsystem()
3. Refactor cmd_run() to use RunContext
4. Refactor cmd_exec() to use ExecContext
5. Update kernel_main() to call process_all_vms()
6. Remove old shared process table (processes[], progpool[])
7. Test independently: run-only, exec-only, then both together

*/


// Add to your kernel_main() loop:
void process_all_vms() {
    tick_run_processes(100);
    tick_exec_processes(100);
    tick_elf_processes();          // ← new
}
extern "C" void kernel_main(uint32_t magic, uint32_t multiboot_addr) {
    // --- INITIALIZATION --- (unchanged)
    static uint8_t kernelheap[1024 * 1024 * 8];
    g_allocator.init(kernelheap, sizeof(kernelheap));
    
    multiboot_info* mbi = (multiboot_info*)multiboot_addr;
    if (!(mbi->flags & (1 << 12))) return;

    fb_info = { 
        (uint32_t*)(uint64_t)mbi->framebuffer_addr, 
        mbi->framebuffer_width, 
        mbi->framebuffer_height, 
        mbi->framebuffer_pitch 
    };
    
    backbuffer = new uint32_t[fb_info.width * fb_info.height];
    
    g_gfx.init(false);
	init_elf_subsystem();
    initialize_vm_subsystems();
    launch_new_terminal();

    enable_usb_legacy_support();

    for (int i = 0; i < 100000; i++) io_wait_short();

    outb(0x64, 0xFF);
    io_delay_long();
    ps2_flush_output_buffer();
    
    if (initialize_universal_mouse()) {
        wm.print_to_focused("Universal mouse driver initialized.\n");
    } else {
        wm.print_to_focused("WARNING: Mouse initialization failed.\n");
    }

    // Replace the block after disk_init():
	disk_init();
	if (ahci_base) {
		// Read BPB raw (fat32_init disables crypto for sector 0 itself now)
		fat32_init();
		wm.print_to_focused("AHCI disk found.\n");
	} else {
		wm.print_to_focused("AHCI disk NOT found.\n");
	}

	if (current_directory_cluster) {
		
		wm.load_desktop_items();

	} else {
		wm.print_to_focused("FAT32 init failed.\n");
	}
    extract_busybox_to_filesystem();
    init_screen_timer(30);

    uint32_t last_paint_tick = 0;
    const uint32_t TICKS_PER_FRAME = 1;

    int prev_mouse_x = mouse_x;
    int prev_mouse_y = mouse_y;
    
    g_gfx.clear_screen(ColorPalette::DESKTOP_BLUE);

    // =============================================================================
    // MAIN LOOP - PERFECT: KEYBOARD + MOUSE CLICKS BOTH WORK
    // =============================================================================
    for (;;) {
        // **CRITICAL MOUSE FIX #1**: Save mouse state BEFORE polling
        bool prev_left = mouse_left_down;
        bool prev_right = mouse_right_down;

        // 1. Poll input (updates mouse_left_down, mouse_right_down, last_key_press)
        poll_input_universal();
        process_all_vms();

        // **CRITICAL MOUSE FIX #2**: Detect clicks using PREVIOUS frame state
        bool leftClickedThisFrame = (mouse_left_down && !prev_left);
        bool rightClickedThisFrame = (mouse_right_down && !prev_right);

        // 2. Set input flags
        bool mouse_moved = (mouse_x != prev_mouse_x || mouse_y != prev_mouse_y);
        bool key_pressed = (last_key_press != 0);

        if (key_pressed || mouse_moved || leftClickedThisFrame || rightClickedThisFrame) {
            g_evt_input = true;
            g_input_state.hasNewInput = true;
            prev_mouse_x = mouse_x;
            prev_mouse_y = mouse_y;
        }

        // 3. Timer
        static uint32_t poll_counter = 0;
        if (++poll_counter >= 500) {
            poll_counter = 0;
            g_evt_timer = true;
            g_timer_ticks++;
        }

        // 4. Handle input with proper isolation
		if (g_evt_input) {
			g_evt_input = false;
			
			// **CRITICAL FIX**: Only feed to VMs if they're ACTIVELY waiting
			// AND the focused window is the one that started the VM
			bool fed_to_vm = false;
			
			if (last_key_press != 0) {
				// Check RUN processes - only feed if they're waiting AND bound to focused window
				for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
					if (run_contexts[i].active && 
						run_contexts[i].vm.waiting_for_input &&
						run_contexts[i].vm.bound_window == wm.get_window(wm.get_focused_idx())) {
						run_contexts[i].vm.feed_input(last_key_press);
						fed_to_vm = true;
						break; // Only feed to ONE VM
					}
				}
				
				// Check EXEC processes - only if no RUN process consumed it
				// After the exec process feeding block, add:
				if (!fed_to_vm) {
					for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
						if (elf_processes[i].active &&
							elf_processes[i].waiting_for_input &&
							elf_processes[i].terminal == wm.get_window(wm.get_focused_idx())) {
							feed_elf_input(i, last_key_press);
							fed_to_vm = true;
							break;
						}
					}
				}
			}
			
			// **KEY FIX**: Only send to WM if VM didn't consume it
			// This allows terminal commands while no VM is waiting
			if (!fed_to_vm) {
				wm.handle_input(last_key_press, mouse_x, mouse_y, 
							   mouse_left_down, leftClickedThisFrame, rightClickedThisFrame);
			} else {
				// VM consumed keyboard, but still process mouse for WM
				wm.handle_input(0, mouse_x, mouse_y, 
							   mouse_left_down, leftClickedThisFrame, rightClickedThisFrame);
			}
			
			if (last_key_press != 0) last_key_press = 0;
			g_evt_dirty = true;
		}

        wm.cleanup_closed_windows();

        // 5. Render
        if (g_evt_timer && (g_timer_ticks - last_paint_tick) >= TICKS_PER_FRAME) {
            if (g_evt_dirty || g_input_state.hasNewInput) {
                last_paint_tick = g_timer_ticks;
                g_evt_dirty = false;
                g_input_state.hasNewInput = false;

                g_gfx.clear_screen(ColorPalette::DESKTOP_BLUE);
                wm.update_all();
                draw_cursor(mouse_x, mouse_y, ColorPalette::CURSOR_WHITE);
                swap_buffers();
            }
            g_evt_timer = false;
        }
    }
}
