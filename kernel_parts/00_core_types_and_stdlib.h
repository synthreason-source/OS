#pragma once
// 00_core_types_and_stdlib.h
// Low-level type defs, libc/libc++ stubs, memory allocator, and central
// forward declarations shared by the rest of the kernel.
// Extracted from kernel.cpp (original lines 1-460) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.

/*
 * OPTIMIZED KERNEL WITH GRAPHICS STATE MANAGEMENT
 * ================================================
 * All graphics rendering uses atomic frame composition
 * Unified color palette prevents inconsistencies
 * State machine ensures complete frames with no trailing
 */
 
#include <cstddef>
#include <cstdarg>
#include <cstdint>
// =============================================================================
// SECTION 1: TYPE DEFS, STDLIB/CXX STUBS, AND LOW-LEVEL FUNCTIONS
// =============================================================================
#define SECTOR_SIZE 512
// Process structure for ELF execution
#define MAX_ELF_PROCESSES 4
#define ELF_STACK_SIZE (64 * 1024)  // 64KB stack per process
#define ELF_HEAP_SIZE (256 * 1024)   // 256KB heap per process
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

extern "C" unsigned long long __udivmoddi4(unsigned long long num,
                                           unsigned long long den,
                                           unsigned long long *rem)
{
    if (den == 0) {
        if (rem) *rem = 0;
        return 0;
    }

    unsigned long long q = 0;
    unsigned long long r = 0;

    for (int i = 63; i >= 0; --i) {
        r <<= 1;
        r |= (num >> i) & 1ULL;
        if (r >= den) {
            r -= den;
            q |= (1ULL << i);
        }
    }

    if (rem) *rem = r;
    return q;
}

extern "C" long long __divmoddi4(long long num,
                                 long long den,
                                 long long *rem)
{
    if (den == 0) {
        if (rem) *rem = 0;
        return 0;
    }

    bool neg_q = (num < 0) ^ (den < 0);
    bool neg_r = (num < 0);

    unsigned long long unum = (num < 0) ? (unsigned long long)(-num) : (unsigned long long)num;
    unsigned long long uden = (den < 0) ? (unsigned long long)(-den) : (unsigned long long)den;

    unsigned long long ur = 0;
    unsigned long long uq = __udivmoddi4(unum, uden, &ur);

    long long q = neg_q ? -(long long)uq : (long long)uq;
    long long r = neg_r ? -(long long)ur : (long long)ur;

    if (rem) *rem = r;
    return q;
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
int fat32_stat_file(const char* filename, uint32_t* size_out);
bool fat32_init();


// objcopy --rename-section emits these as address labels into .rodata.
// Must be declared as incomplete arrays (extern "C" uint8_t name[]) so
// that the identifiers decay to pointers without needing &.
// Using scalar uint8_t and then taking & also resolves, but treating a
// linker label as a single-byte object is undefined behaviour in C++.
extern "C" uint8_t ramdisk_start[];
extern "C" uint8_t ramdisk_end[];
extern "C" uint8_t hello_start[];
extern "C" uint8_t hello_end[];

bool extract_busybox_to_filesystem() {
    uint8_t* start = ramdisk_start;
    uint8_t* end   = ramdisk_end;
    if (end <= start) return false;
    uint32_t size  = (uint32_t)(end - start);
    // Sanity: must be a plausible ELF (>= 52 bytes), not absurdly large.
    if (size < 52 || size > 8 * 1024 * 1024) {
        return false;
    }
    // Check ELF magic before writing to avoid storing garbage on disk.
    if (start[0] != 0x7f || start[1] != 'E' ||
        start[2] != 'L'  || start[3] != 'F') {
        return false;
    }
    // If a "busybox" file already exists with the right size, skip the write
    // to save time on repeated boots.
    fat_dir_entry_t existing;
    uint32_t esec = 0, eoff = 0;
    if (fat32_find_entry("busybox", &existing, &esec, &eoff) == 0) {
        if (existing.file_size == size) return true;  // already current
    }
    int result = fat32_write_file("busybox", start, size);
    return (result == 0);
}

// Write the embedded hello test ELF to FAT32 as "hello".
// Same shape as extract_busybox_to_filesystem.
bool extract_hello_to_filesystem() {
    uint8_t* start = hello_start;
    uint8_t* end   = hello_end;
    if (end <= start) return false;
    uint32_t size  = (uint32_t)(end - start);
    if (size < 52 || size > 1 * 1024 * 1024) return false;
    if (start[0] != 0x7f || start[1] != 'E' ||
        start[2] != 'L'  || start[3] != 'F') return false;

    fat_dir_entry_t existing;
    uint32_t esec = 0, eoff = 0;
    if (fat32_find_entry("hello", &existing, &esec, &eoff) == 0) {
        if (existing.file_size == size) return true;
    }
    int result = fat32_write_file("hello", start, size);
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


// COMPLETE FIXED KERNEL.CPP - BUSYBOX ELF EXEC READY
// Paste this ENTIRE file as your new kernel.cpp. Compiles clean.
// All warnings/errors fixed. Busybox takes terminal control.
// No compiler. Pure ELF loader + x86 emu + ring buffers.

// ===== INCLUDES & DEFS =====
#include <cstddef>
#include <cstdarg>
#include <cstdint>

// Your existing includes/types/stdlib from paste.txt...
// SECTORSIZE removed - use SECTOR_SIZE (defined above)
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
// =============================================================================
// CORRECT ORDER - paste these blocks in this sequence
// =============================================================================

// --- STEP 1: Constants - move these to the TOP, before any class ---
#define INBUFSIZE   512
#define OUTBUFSIZE  4096
#define SB          0x80000000u
#define MAXelf_processes 4
#define ELFSTACKSIZE     (64  * 1024)
#define ELFHEAPSIZE      (256 * 1024)

// --- STEP 2: ElfProcess struct - move before TerminalWindow ---
struct ElfProcess {
    int input_pos = 0;

    uint32_t entry_point = 0;   // full virtual address (e_entry)
    uint32_t vaddr_base  = 0;   // min PT_LOAD vaddr (== physical base in Bochs)
    uint32_t vaddr_end   = 0;   // max PT_LOAD vaddr + memsz (exclusive)
    uint8_t* memory_base = nullptr;
    uint32_t memory_size = 0;
    uint8_t* stack       = nullptr;
    uint32_t esp = 0, eip = 0;
    TerminalWindow* terminal = nullptr;
    char cmdline[256] = {0};
    bool waiting_for_input = false;
    bool completed = false;
    int exit_code  = 0;
    bool active = false;
    bool cpu_initialized = false;
    
    unsigned int brk_addr = 0;
    char inbuf[INBUFSIZE];   int in_head=0,  in_tail=0;
    char outbuf[OUTBUFSIZE]; int out_head=0, out_tail=0;
};

// --- STEP 3: Global array - move before TerminalWindow ---

static ElfProcess elf_processes[MAX_ELF_PROCESSES];

// --- STEP 4: Ring buffer helpers - move before TerminalWindow ---
bool in_empty(int slot) {
    return elf_processes[slot].in_head == elf_processes[slot].in_tail;
}
bool out_empty(int slot) {
    return elf_processes[slot].out_head == elf_processes[slot].out_tail;
}
void push_input(int slot, char c) {
    ElfProcess& p = elf_processes[slot];
    int next = p.in_head + 1;
    if (next == INBUFSIZE) next = 0;
    if (next != p.in_tail) {
        p.inbuf[p.in_head] = c;
        p.in_head = next;
    }
}
char pop_input(int slot) {
    ElfProcess& p = elf_processes[slot];
    if (in_empty(slot)) return 0;
    char c = p.inbuf[p.in_tail];
    p.in_tail = (p.in_tail + 1) % INBUFSIZE;
    return c;
}
void push_output(int slot, char c) {
    ElfProcess& p = elf_processes[slot];
    int next = p.out_head + 1;
    if (next == OUTBUFSIZE) next = 0;
    if (next != p.out_tail) {
        p.outbuf[p.out_head] = c;
        p.out_head = next;
    }
}
char pop_output(int slot) {
    ElfProcess& p = elf_processes[slot];
    if (out_empty(slot)) return 0;
    char c = p.outbuf[p.out_tail];
    p.out_tail = (p.out_tail + 1) % OUTBUFSIZE;
    return c;
}

// --- STEP 5: Bochs externs - move before TerminalWindow ---
extern "C" void bochs_set_process_memory(
    uint8_t* base, uint32_t size, uint32_t vaddr_base);
extern "C" void bochs_cpu_init();
extern "C" void bochs_cpu_prewarm();
extern "C" void bochs_cpu_set_eip(uint32_t eip);
extern "C" void bochs_cpu_set_esp(uint32_t esp);
extern "C" int  bochs_cpu_tick(int steps);
extern "C" uint32_t bochs_cpu_get_eax();
extern "C" uint32_t bochs_cpu_get_eip();
// New: slot management, brk, I/O callbacks, and input-wait detection
extern "C" void bochs_activate_slot(int slot);
extern "C" void bochs_finalize_process_memory();
extern "C" void bochs_set_brk(int slot, uint32_t brk_addr);
extern "C" void bochs_register_io_callbacks(
    int slot,
    int  (*read_cb )(int),
    void (*write_cb)(int, char),
    void (*exit_cb )(int, int));
extern "C" bool bochs_process_wants_input(int slot);

// ── In-kernel TCC compiler (tcc_kernel.cpp + i386-libtcc-kern.a) ─────────────
// tcc_kernel_version() == 0 → stub (no TCC), 2 → real in-kernel TCC.
extern "C" int  tcc_kernel_version(void);
extern "C" void tcc_kernel_cmd_cc(void* terminal, const char* src_name,
                                  const char* out_name);
// Heavy "reset everything" — called between ELF runs so each launch
// starts from the same state as the first one. See the comment block
// over its definition in bochs_glue.cpp for the full rationale.
extern "C" void bochs_reset_all_slots();

// Surgical per-slot release — called when ONE slot's process exits
// but other slots are still running. Wipes only that slot's glue
// state (mapping, mem_base pointer, saved CPU snapshot). Unlike
// bochs_reset_all_slots(), does NOT touch BX_CPU(0), so peer slots
// keep executing safely. Must be called BEFORE the kernel frees the
// slot's backing slab so the mapping_unregister still has a valid
// vaddr range to look up.
extern "C" void bochs_release_slot(int slot);

// Forward declarations for the ELF loader helpers and IO callbacks defined
// later in this file. busybox/hello use the same lazy-init pattern as
// load_and_execute_elf (cpu_initialized=false, no bochs_cpu_init here).
// start_elf_process/load_elf_image_to_slab are kept for test_main usage.
static bool load_elf_image_to_slab(int slot, const unsigned char* elf,
                                   unsigned int elf_size, unsigned int& entry_out);
static bool start_elf_process(int slot, const unsigned char* elf,
                              unsigned int elf_size);
// IO callbacks — forward-declared so the `test` command handler can
// restore them after test_module_run() overwrites slot 0's callbacks.
static int  elf_io_read (int slot);
static void elf_io_write(int slot, char c);
static void elf_io_exit (int slot, int code);

// test_module.cpp holds the test execution code (formerly the standalone
// test_main.cpp). It is activated by typing `test` in a terminal. The module
// renders a three-row "VGA-style" overlay (breadcrumbs / fault tag / GUEST
// row) by calling back through a TestSink — it has no knowledge of windows.
//
// The kernel side, below, owns:
//   - g_test_vga[]   : a 3x80 cell buffer the module writes via vga_cell()
//   - test_sink_*    : the C callbacks the module invokes
//   - g_test_overlay_owner : which TerminalWindow currently shows the overlay
// The TerminalWindow::draw() method paints g_test_vga[] as three colored
// rows at the top of its content area whenever it owns the overlay.
#include "../test_module.h"

// =====================================================================
// C++ global constructor (__init_array) walk — runs ONCE at boot.
//
// boot.S jumps straight from BSS-zero into kernel_main; it does NOT walk
// __init_array. That means the file-scope C++ constructors that build
// the Bochs core objects (bx_cpu(0), bx_mem, the CPUID parameter
// objects in bochs_infra.cpp, icache's pageWriteStampTable, ...) never
// run unless something explicitly walks the array.
//
// Previously the ONLY caller was test_module_run() (via its private
// run_init_array_once()). So a freshly booted system that launched an
// ELF in the Bochs emulator window *without first typing `test`* called
// bochs_cpu_init() -> BX_CPU(0)->initialize() against raw, zero-filled
// BSS objects — null vtables — and instantly faulted. The emulator
// window's guest trapped out through the port-0xE8 exit stub on its
// very first tick, so the window appeared to "crash / autoclose" the
// first time it was used.
//
// The fix: walk __init_array here, once, from kernel_main, before any
// Bochs entry point can be reached. test_module's own guard
// (g_init_array_done) plus our call to test_module_mark_ctors_done()
// guarantees the constructors are never run a second time by `test`.
extern "C" void (*__init_array_start[])();
extern "C" void (*__init_array_end[])();

static bool g_kernel_ctors_done = false;

static void kernel_run_global_ctors_once() {
    if (g_kernel_ctors_done) return;
    g_kernel_ctors_done = true;
    for (void (**p)() = __init_array_start; p < __init_array_end; ++p) {
        if (*p) (*p)();
    }
}

struct TestVgaCell { char ch; uint8_t attr; };
static TestVgaCell g_test_vga[3][80];
static bool        g_test_overlay_active = false;
// Forward decl: set to the TerminalWindow that ran `test`. Declared void*
// here because TerminalWindow is defined much further down; the command
// handler casts it back.
static void*       g_test_overlay_owner  = nullptr;

// Clear the overlay buffer to blank grey-on-black cells.
static void test_vga_clear() {
    for (int r = 0; r < 3; ++r)
        for (int c = 0; c < 80; ++c) {
            g_test_vga[r][c].ch   = ' ';
            g_test_vga[r][c].attr = 0x0F;
        }
}

// --- TestSink callbacks (C linkage so the module can take their address) ---
// vga_cell: the module's faithful reproduction of writing VGA text memory.
extern "C" void test_sink_vga_cell(int row, int col, char ch, uint8_t attr) {
    if (row < 0 || row >= 3 || col < 0 || col >= 80) return;
    g_test_vga[row][col].ch   = ch;
    g_test_vga[row][col].attr = attr;
    g_test_overlay_active     = true;
}
// put_line: forwarded to the owning terminal's console_print (defined after
// TerminalWindow, since it needs the full class — see test_sink_put_line()).
extern "C" void test_sink_put_line(const char* s);
// flush: repaints the whole screen and swaps buffers mid-test. Defined
// after WindowManager / swap_buffers are available (see test_sink_flush()).
// Without this the GUI would freeze for the whole blocking test run and
// the overlay would never become visible.
extern "C" void test_sink_flush(void);

// --- STEP 6: NOW TerminalWindow and everything else follows ---
// Moved here to be visible to all classes and functions
static bool    g_fs_encryption_enabled = false;
