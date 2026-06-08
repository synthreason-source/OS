// =====================================================================
// tcc_glue.cpp — Tiny C Compiler integration for the freestanding kernel.
// Compile with: -DTCC_GLUE (Makefile.tcc does this automatically)
// =====================================================================

#ifndef TCC_GLUE
#error "tcc_glue.cpp must be compiled with -DTCC_GLUE"
#endif

#include "tcc_glue.h"

// ── Freestanding types ────────────────────────────────────────────────────
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef int                int32_t;
// uintptr_t: pointer-sized unsigned integer on i386 = 32-bit
typedef unsigned int       uintptr_t;
typedef unsigned int       size_t;

// ── Kernel services ───────────────────────────────────────────────────────
// fat32_* are plain C++ functions in kernel.cpp (no extern "C" there),
// so we must declare them WITHOUT extern "C" to match their mangled names.
// fat_dir_entry_t matches kernel.cpp's packed typedef exactly.
typedef struct {
    char     name[11];
    uint8_t  attr, ntres, crt_time_tenth;
    uint16_t crt_time, crt_date, lst_acc_date, fst_clus_hi;
    uint16_t wrt_time, wrt_date, fst_clus_lo;
    uint32_t file_size;
} __attribute__((packed)) fat_dir_entry_t;

char* fat32_read_file_as_string(const char* filename);
int   fat32_write_file(const char* filename, const void* data, uint32_t size);
int   fat32_find_entry(const char* name, fat_dir_entry_t* out,
                       uint32_t* sec, uint32_t* off);

// live_breadcrumb is declared extern "C" in kernel.cpp.
extern "C" void live_breadcrumb(int slot, char ch);

// Bump-pool allocator from bochs_cstubs.c (compiled as C, so extern "C").
extern "C" void* bochs_pool_alloc(size_t n);

// Embedded libtcc.so linker symbols injected by objcopy (Makefile.tcc).
// objcopy --binary-architecture i386 emits these as plain C symbols,
// not C++ mangled, so they must be declared extern "C" here.
extern "C" uint8_t libtcc_start[];
extern "C" uint8_t libtcc_end[];

// ── Tiny string/memory helpers (no libc) ─────────────────────────────────
static size_t   k_strlen(const char* s) { size_t n=0; while(s&&s[n])n++; return n; }
static void     k_memcpy(void* d, const void* s, size_t n) {
    uint8_t* dd=(uint8_t*)d; const uint8_t* ss=(const uint8_t*)s; while(n--)*dd++=*ss++;
}
static void     k_memset(void* d, int c, size_t n) {
    uint8_t* p=(uint8_t*)d; while(n--)*p++=(uint8_t)c;
}
static int      k_strcmp(const char* a, const char* b) {
    while(*a&&*a==*b){a++;b++;} return (unsigned char)*a-(unsigned char)*b;
}
static int      k_strncmp(const char* a, const char* b, size_t n) {
    while(n&&*a&&*a==*b){a++;b++;n--;} return n?(unsigned char)*a-(unsigned char)*b:0;
}
// Strip file extension, write result into dst (max bytes). Returns chars written.
static int k_strip_ext(char* dst, const char* src, int max) {
    int len=(int)k_strlen(src), dot=-1;
    for(int i=len-1;i>=0;--i){ if(src[i]=='.')dot=i; if(src[i]=='/'||src[i]=='\\')break; }
    int copy=(dot>0)?dot:len; if(copy>=max)copy=max-1;
    for(int i=0;i<copy;++i) { dst[i]=src[i]; }
    dst[copy]='\0'; return copy;
}

// ── Debug console (slot 32) ───────────────────────────────────────────────
#define TCC_BC_SLOT 32
static void tcc_bc(char c) { live_breadcrumb(TCC_BC_SLOT, c); }
static void tcc_puts(const char* s) { while(s&&*s)tcc_bc(*s++); }

// ── Error buffer ──────────────────────────────────────────────────────────
#define TCC_ERRBUF_SIZE 512
static char g_tcc_error_buf[TCC_ERRBUF_SIZE];
static bool g_tcc_had_error = false;

// ── libtcc execution slab ─────────────────────────────────────────────────
// ELF segments copied here and relocated in place.
// 4 MiB > stripped TCC 0.9.27 i386 .so (~800 KiB).
#define LIBTCC_SLAB_BYTES (4 * 1024 * 1024)
static uint8_t  g_libtcc_slab[LIBTCC_SLAB_BYTES] __attribute__((aligned(16)));
static uint32_t g_libtcc_slab_used = 0;

// ── Module state ──────────────────────────────────────────────────────────
static bool g_tcc_init_done = false;
static bool g_tcc_available = false;
static bool g_tcc_busy      = false;

// ── Minimal i386 ELF loader ───────────────────────────────────────────────
struct Elf32_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version, e_entry, e_phoff, e_shoff, e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
};
struct Elf32_Phdr {
    uint32_t p_type, p_offset, p_vaddr, p_paddr;
    uint32_t p_filesz, p_memsz, p_flags, p_align;
};
struct Elf32_Shdr {
    uint32_t sh_name, sh_type, sh_flags, sh_addr;
    uint32_t sh_offset, sh_size, sh_link, sh_info;
    uint32_t sh_addralign, sh_entsize;
};
struct Elf32_Sym {
    uint32_t st_name, st_value, st_size;
    uint8_t  st_info, st_other;
    uint16_t st_shndx;
};
struct Elf32_Rel  { uint32_t r_offset, r_info; };
struct Elf32_Rela { uint32_t r_offset, r_info; int32_t r_addend; };

#define PT_LOAD     1u
#define SHT_DYNSYM  11u
#define SHT_STRTAB  3u
#define SHT_REL     9u
#define SHT_RELA    4u

#define R_386_NONE      0u
#define R_386_32        1u
#define R_386_PC32      2u
#define R_386_GLOB_DAT  6u
#define R_386_JMP_SLOT  7u
#define R_386_RELATIVE  8u

#define ELF32_R_SYM(i)  ((i) >> 8)
#define ELF32_R_TYPE(i) ((i) & 0xFFu)

struct LibtccLoad {
    uint8_t*   base;
    uint32_t   bias;          // = min_vaddr at load time
    Elf32_Sym* dynsym;
    uint32_t   dynsym_count;
    char*      dynstr;
};
static LibtccLoad g_ll;

// Return host pointer to a named symbol in the loaded slab, or nullptr.
static void* libtcc_sym_ptr(const char* name) {
    if (!g_ll.dynsym || !g_ll.dynstr) return nullptr;
    for (uint32_t i = 0; i < g_ll.dynsym_count; ++i) {
        Elf32_Sym& s = g_ll.dynsym[i];
        if (!s.st_name || !s.st_shndx) continue;
        if (k_strcmp(g_ll.dynstr + s.st_name, name) == 0)
            return g_ll.base + (s.st_value - g_ll.bias);
    }
    return nullptr;
}

static void apply_rel(uint32_t* patch, uint32_t r_type,
                      uint32_t sym_val, uint32_t addend) {
    switch (r_type) {
    case R_386_NONE:     break;
    case R_386_32:       *patch  = sym_val + addend; break;
    case R_386_PC32:     *patch  = sym_val + addend
                                   - (uint32_t)(uintptr_t)patch; break;
    case R_386_RELATIVE: *patch += (uint32_t)(uintptr_t)g_ll.base - g_ll.bias; break;
    case R_386_GLOB_DAT: *patch  = sym_val; break;
    case R_386_JMP_SLOT: *patch  = sym_val; break;
    default: break;
    }
}

// Load libtcc from `elf_data` (in-kernel .rodata) into g_libtcc_slab.
// Returns 0 on success.
static int libtcc_elf_load(const uint8_t* elf_data, uint32_t elf_size) {
    if (elf_size < sizeof(Elf32_Ehdr)) return -1;
    const Elf32_Ehdr* eh = (const Elf32_Ehdr*)elf_data;
    if (eh->e_ident[0]!= 0x7F || eh->e_ident[1]!='E' ||
        eh->e_ident[2]!= 'L'  || eh->e_ident[3]!='F' ||
        eh->e_ident[4]!= 1) return -1;   // must be 32-bit ELF

    // Phase 1: compute vaddr extent
    uint32_t min_va = 0xFFFFFFFFu, max_va = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        const Elf32_Phdr* ph = (const Elf32_Phdr*)
            (elf_data + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_vaddr < min_va) min_va = ph->p_vaddr;
        uint32_t end = ph->p_vaddr + ph->p_memsz;
        if (end > max_va) max_va = end;
    }
    if (min_va == 0xFFFFFFFFu || max_va <= min_va) return -1;
    uint32_t extent = max_va - min_va;
    if (extent > LIBTCC_SLAB_BYTES) return -1;

    uint8_t* slab = g_libtcc_slab;
    k_memset(slab, 0, extent);
    g_ll.base  = slab;
    g_ll.bias  = min_va;

    // Phase 2: copy PT_LOAD segments
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        const Elf32_Phdr* ph = (const Elf32_Phdr*)
            (elf_data + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        uint32_t dest = ph->p_vaddr - min_va;
        if (dest + ph->p_filesz > LIBTCC_SLAB_BYTES) return -1;
        k_memcpy(slab + dest, elf_data + ph->p_offset, ph->p_filesz);
        if (ph->p_memsz > ph->p_filesz)
            k_memset(slab + dest + ph->p_filesz, 0,
                     ph->p_memsz - ph->p_filesz);
    }
    g_libtcc_slab_used = extent;

    // Phase 3: locate dynsym / dynstr / rel sections
    if (!eh->e_shoff || !eh->e_shnum) return -1;
    const Elf32_Shdr* shdrs = (const Elf32_Shdr*)(elf_data + eh->e_shoff);
    const char* shstrtab = nullptr;
    if (eh->e_shstrndx < eh->e_shnum)
        shstrtab = (const char*)(elf_data + shdrs[eh->e_shstrndx].sh_offset);

    const Elf32_Sym* raw_dynsym    = nullptr;
    uint32_t         raw_dynsym_cnt = 0;
    const char*      raw_dynstr    = nullptr;

    struct RelSec { const uint8_t* data; uint32_t size, entsize; bool rela; };
    static RelSec relsecs[16];
    int relsec_cnt = 0;

    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        const Elf32_Shdr& sh = shdrs[i];
        if (sh.sh_type == SHT_DYNSYM) {
            raw_dynsym     = (const Elf32_Sym*)(elf_data + sh.sh_offset);
            raw_dynsym_cnt = sh.sh_size / sizeof(Elf32_Sym);
        } else if (sh.sh_type == SHT_STRTAB && i != eh->e_shstrndx) {
            bool is_dynstr = shstrtab && sh.sh_name &&
                             k_strcmp(shstrtab + sh.sh_name, ".dynstr") == 0;
            if (is_dynstr || !raw_dynstr)
                raw_dynstr = (const char*)(elf_data + sh.sh_offset);
        } else if ((sh.sh_type == SHT_REL || sh.sh_type == SHT_RELA)
                   && relsec_cnt < 16) {
            uint32_t esz = sh.sh_entsize ? sh.sh_entsize
                : (sh.sh_type == SHT_RELA ? (uint32_t)sizeof(Elf32_Rela)
                                           : (uint32_t)sizeof(Elf32_Rel));
            relsecs[relsec_cnt++] = {
                elf_data + sh.sh_offset, sh.sh_size, esz,
                sh.sh_type == SHT_RELA
            };
        }
    }
    if (!raw_dynsym || !raw_dynstr) return -1;

    // Point dynsym/dynstr into slab if the section was loaded in a PT_LOAD;
    // otherwise copy to slab tail.
    g_ll.dynsym_count = raw_dynsym_cnt;
    g_ll.dynsym = nullptr;
    g_ll.dynstr = nullptr;
    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        const Elf32_Shdr& sh = shdrs[i];
        if (!g_ll.dynsym && sh.sh_type == SHT_DYNSYM
            && sh.sh_addr >= min_va)
            g_ll.dynsym = (Elf32_Sym*)(slab + (sh.sh_addr - min_va));
        if (!g_ll.dynstr && sh.sh_type == SHT_STRTAB
            && sh.sh_addr >= min_va && shstrtab && sh.sh_name
            && k_strcmp(shstrtab + sh.sh_name, ".dynstr") == 0)
            g_ll.dynstr = (char*)(slab + (sh.sh_addr - min_va));
    }
    if (!g_ll.dynsym) {
        uint32_t sz = raw_dynsym_cnt * sizeof(Elf32_Sym);
        if (g_libtcc_slab_used + sz > LIBTCC_SLAB_BYTES) return -1;
        k_memcpy(slab + g_libtcc_slab_used, raw_dynsym, sz);
        g_ll.dynsym = (Elf32_Sym*)(slab + g_libtcc_slab_used);
        g_libtcc_slab_used += sz;
    }
    if (!g_ll.dynstr) {
        // Conservative: copy whole strtab section.
        for (uint16_t i = 0; i < eh->e_shnum && !g_ll.dynstr; ++i) {
            const Elf32_Shdr& sh = shdrs[i];
            if (sh.sh_type == SHT_STRTAB && i != eh->e_shstrndx) {
                if (g_libtcc_slab_used + sh.sh_size > LIBTCC_SLAB_BYTES)
                    return -1;
                k_memcpy(slab + g_libtcc_slab_used,
                         elf_data + sh.sh_offset, sh.sh_size);
                g_ll.dynstr = (char*)(slab + g_libtcc_slab_used);
                g_libtcc_slab_used += sh.sh_size;
            }
        }
        if (!g_ll.dynstr) return -1;
    }

    // Phase 4: apply relocations
    for (int ri = 0; ri < relsec_cnt; ++ri) {
        const RelSec& rs = relsecs[ri];
        for (uint32_t off = 0; off + rs.entsize <= rs.size; off += rs.entsize) {
            const uint8_t* entry = rs.data + off;
            uint32_t r_offset, r_info;
            int32_t  r_addend = 0;
            if (rs.rela) {
                auto* r = (const Elf32_Rela*)entry;
                r_offset = r->r_offset; r_info = r->r_info;
                r_addend = r->r_addend;
            } else {
                auto* r = (const Elf32_Rel*)entry;
                r_offset = r->r_offset; r_info = r->r_info;
            }
            if (r_offset < min_va || r_offset >= max_va) continue;
            uint32_t* patch = (uint32_t*)(slab + (r_offset - min_va));
            if (!rs.rela) r_addend = (int32_t)*patch;

            uint32_t sym_val = 0;
            uint32_t sym_idx = ELF32_R_SYM(r_info);
            if (sym_idx && sym_idx < raw_dynsym_cnt) {
                const Elf32_Sym& sym = raw_dynsym[sym_idx];
                if (sym.st_shndx)
                    sym_val = (uint32_t)(uintptr_t)
                              (slab + (sym.st_value - min_va));
            }
            apply_rel(patch, ELF32_R_TYPE(r_info),
                      sym_val, (uint32_t)r_addend);
        }
    }
    return 0;
}

// ── TCC function-pointer table ────────────────────────────────────────────
typedef void* TCCState;
#define TCC_OUTPUT_MEMORY 1
#define TCC_OUTPUT_EXE    2

struct TccFnTable {
    TCCState* (*tcc_new)(void);
    void      (*tcc_delete)(TCCState*);
    void      (*tcc_set_error_func)(TCCState*, void*,
                   void(*)(void*, const char*));
    int       (*tcc_set_output_type)(TCCState*, int);
    int       (*tcc_add_include_path)(TCCState*, const char*);
    int       (*tcc_define_symbol)(TCCState*, const char*, const char*);
    int       (*tcc_add_file)(TCCState*, const char*);
    int       (*tcc_compile_string)(TCCState*, const char*);
    int       (*tcc_output_file)(TCCState*, const char*);
    int       (*tcc_relocate)(TCCState*, void*);
    void*     (*tcc_get_symbol)(TCCState*, const char*);
    int       (*tcc_get_memory)(TCCState*, void**, int*);  // optional
    void      (*tcc_set_lib_path)(TCCState*, const char*); // optional
};
static TccFnTable g_tcc;

template<typename T>
static bool resolve(const char* name, T& out) {
    void* p = libtcc_sym_ptr(name);
    if (!p) { tcc_puts("tcc: missing: "); tcc_puts(name); tcc_puts("\n"); }
    out = (T)p;
    return p != nullptr;
}

// ── TCC error callback ────────────────────────────────────────────────────
static void tcc_error_cb(void*, const char* msg) {
    if (!msg) return;
    g_tcc_had_error = true;
    int used = (int)k_strlen(g_tcc_error_buf);
    int room = TCC_ERRBUF_SIZE - used - 2;
    if (room <= 0) return;
    for (int i = 0; msg[i] && i < room; ++i)
        g_tcc_error_buf[used + i] = msg[i];
    int end = (int)k_strlen(g_tcc_error_buf);
    if (end + 1 < TCC_ERRBUF_SIZE) {
        g_tcc_error_buf[end]   = '\n';
        g_tcc_error_buf[end+1] = '\0';
    }
}

// ── ELF32 wrapper ─────────────────────────────────────────────────────────
// Wraps a flat in-memory code blob into a minimal i386 ELF32 executable.
// Load address 0x08048000 matches hello.c / guest.c convention.
static uint8_t* wrap_elf32(const uint8_t* code, uint32_t code_size,
                            uint32_t entry_off, uint32_t* out_total) {
    const uint32_t VBASE    = 0x08048000u;
    const uint32_t CODE_OFF = 0x1000u;
    uint32_t total = CODE_OFF + code_size;
    uint8_t* buf = new uint8_t[total];
    if (!buf) { *out_total = 0; return nullptr; }
    k_memset(buf, 0, total);

    Elf32_Ehdr* eh = (Elf32_Ehdr*)buf;
    eh->e_ident[0]=0x7F; eh->e_ident[1]='E';
    eh->e_ident[2]='L';  eh->e_ident[3]='F';
    eh->e_ident[4]=1;    // 32-bit
    eh->e_ident[5]=1;    // little-endian
    eh->e_ident[6]=1;    // ELF version
    eh->e_type      = 2; // ET_EXEC
    eh->e_machine   = 3; // EM_386
    eh->e_version   = 1;
    eh->e_entry     = VBASE + CODE_OFF + entry_off;
    eh->e_phoff     = (uint32_t)sizeof(Elf32_Ehdr);
    eh->e_ehsize    = (uint16_t)sizeof(Elf32_Ehdr);
    eh->e_phentsize = (uint16_t)sizeof(Elf32_Phdr);
    eh->e_phnum     = 1;
    eh->e_shentsize = (uint16_t)sizeof(Elf32_Shdr);

    Elf32_Phdr* ph = (Elf32_Phdr*)(buf + sizeof(Elf32_Ehdr));
    ph->p_type   = PT_LOAD;
    ph->p_offset = CODE_OFF;
    ph->p_vaddr  = VBASE + CODE_OFF;
    ph->p_paddr  = VBASE + CODE_OFF;
    ph->p_filesz = code_size;
    ph->p_memsz  = code_size + 0x10000u;  // headroom for BSS / stack
    ph->p_flags  = 5;      // PF_R | PF_X
    ph->p_align  = 0x1000u;

    k_memcpy(buf + CODE_OFF, code, code_size);
    *out_total = total;
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────

extern "C" bool extract_libtcc_to_filesystem(void) {
    const uint8_t* start = libtcc_start;
    const uint8_t* end   = libtcc_end;
    if (end <= start) return false;
    uint32_t size = (uint32_t)(end - start);
    if (size < 52) return false;
    if (start[0] != 0x7F || start[1] != 'E' ||
        start[2] != 'L'  || start[3] != 'F') return false;

    // Skip write if already present at the right size (idempotent).
    fat_dir_entry_t existing;
    uint32_t esec = 0, eoff = 0;
    if (fat32_find_entry("libtcc.so", &existing, &esec, &eoff) == 0)
        if (existing.file_size == size) return true;

    return fat32_write_file("libtcc.so", start, size) == 0;
}

extern "C" int tcc_module_init(void) {
    if (g_tcc_init_done) return g_tcc_available ? 0 : -1;
    g_tcc_init_done = true;
    g_tcc_available = false;

    tcc_bc('I');

    const uint8_t* elf_data = libtcc_start;
    uint32_t elf_size = (uint32_t)(libtcc_end - libtcc_start);

    if (elf_size < 52) {
        tcc_puts("tcc_init: embedded libtcc too small\n");
        return -1;
    }
    if (elf_data[0] != 0x7F || elf_data[1] != 'E' ||
        elf_data[2] != 'L'  || elf_data[3] != 'F') {
        tcc_puts("tcc_init: embedded libtcc is not ELF\n");
        return -1;
    }
    tcc_bc('L');

    if (libtcc_elf_load(elf_data, elf_size) != 0) {
        tcc_puts("tcc_init: ELF load/reloc failed\n");
        return -1;
    }
    tcc_bc('E');

    // Resolve required symbols.
    bool ok = true;
    ok &= resolve("tcc_new",             g_tcc.tcc_new);
    ok &= resolve("tcc_delete",          g_tcc.tcc_delete);
    ok &= resolve("tcc_set_error_func",  g_tcc.tcc_set_error_func);
    ok &= resolve("tcc_set_output_type", g_tcc.tcc_set_output_type);
    ok &= resolve("tcc_add_include_path",g_tcc.tcc_add_include_path);
    ok &= resolve("tcc_define_symbol",   g_tcc.tcc_define_symbol);
    ok &= resolve("tcc_add_file",        g_tcc.tcc_add_file);
    ok &= resolve("tcc_compile_string",  g_tcc.tcc_compile_string);
    ok &= resolve("tcc_output_file",     g_tcc.tcc_output_file);
    ok &= resolve("tcc_relocate",        g_tcc.tcc_relocate);
    ok &= resolve("tcc_get_symbol",      g_tcc.tcc_get_symbol);
    // Optional — tolerate absence on older TCC builds.
    resolve("tcc_get_memory",  g_tcc.tcc_get_memory);
    resolve("tcc_set_lib_path",g_tcc.tcc_set_lib_path);

    if (!ok) {
        tcc_puts("tcc_init: required symbols missing\n");
        return -1;
    }
    tcc_bc('R');

    g_tcc_available = true;
    return 0;
}

extern "C" int tcc_module_available(void) { return g_tcc_available ? 1 : 0; }

extern "C" const char* tcc_last_error(void) { return g_tcc_error_buf; }

extern "C" int tcc_compile_file(const char*        src_filename,
                                 const char*        out_filename,
                                 const char* const* extra_flags) {
    if (!g_tcc_available) return TCC_ERR_NOT_INIT;
    if (!src_filename)    return TCC_ERR_NO_SRC;
    if (g_tcc_busy)       return TCC_ERR_COMPILE;

    g_tcc_busy = true;
    g_tcc_had_error = false;
    k_memset(g_tcc_error_buf, 0, TCC_ERRBUF_SIZE);

    // Derive output name if not given.
    char derived_out[64];
    if (!out_filename || !*out_filename) {
        k_strip_ext(derived_out, src_filename, 63);
        out_filename = derived_out;
    }

    // Read source from FAT32.
    char* src = fat32_read_file_as_string(src_filename);
    if (!src) {
        tcc_puts("tcc: source not found: "); tcc_puts(src_filename); tcc_puts("\n");
        g_tcc_busy = false;
        return TCC_ERR_NO_SRC;
    }
    tcc_bc('C');

    TCCState* ctx = g_tcc.tcc_new();
    if (!ctx) { delete[] src; g_tcc_busy = false; return TCC_ERR_NOMEM; }

    g_tcc.tcc_set_error_func(ctx, nullptr, tcc_error_cb);
    g_tcc.tcc_set_output_type(ctx, TCC_OUTPUT_MEMORY);

    // Standard freestanding defines matching how guest ELFs are built.
    g_tcc.tcc_define_symbol(ctx, "__KERNEL_GUEST__", "1");
    g_tcc.tcc_define_symbol(ctx, "__i386__",         "1");

    if (extra_flags) {
        for (int i = 0; extra_flags[i]; ++i) {
            const char* f = extra_flags[i];
            if (k_strncmp(f, "-D", 2) == 0)
                g_tcc.tcc_define_symbol(ctx, f + 2, nullptr);
            else if (k_strncmp(f, "-I", 2) == 0)
                g_tcc.tcc_add_include_path(ctx, f + 2);
        }
    }

    tcc_bc('S');
    int rc = g_tcc.tcc_compile_string(ctx, src);
    delete[] src;

    if (rc != 0 || g_tcc_had_error) {
        tcc_puts("tcc: compile error\n");
        g_tcc.tcc_delete(ctx);
        g_tcc_busy = false;
        return TCC_ERR_COMPILE;
    }
    tcc_bc('K');

    // Relocate in-memory. TCC_RELOCATE_AUTO = (void*)1 per tcc.h.
    rc = g_tcc.tcc_relocate(ctx, (void*)1);
    if (rc != 0) {
        tcc_puts("tcc: relocation failed\n");
        g_tcc.tcc_delete(ctx);
        g_tcc_busy = false;
        return TCC_ERR_COMPILE;
    }
    tcc_bc('X');

    // Find entry point symbol.
    void* entry_ptr = g_tcc.tcc_get_symbol(ctx, "_start");
    if (!entry_ptr) entry_ptr = g_tcc.tcc_get_symbol(ctx, "main");

    int result = TCC_ERR_COMPILE;

    // ── Path A: tcc_get_memory() (preferred) ─────────────────────────
    if (g_tcc.tcc_get_memory) {
        void* mem_ptr = nullptr;
        int   mem_len = 0;
        if (g_tcc.tcc_get_memory(ctx, &mem_ptr, &mem_len) == 0
            && mem_ptr && mem_len > 0) {
            uint32_t entry_off = 0;
            if (entry_ptr
                && (uintptr_t)entry_ptr >= (uintptr_t)mem_ptr)
                entry_off = (uint32_t)(
                    (uintptr_t)entry_ptr - (uintptr_t)mem_ptr);

            uint8_t* code = new uint8_t[(uint32_t)mem_len];
            if (code) {
                k_memcpy(code, mem_ptr, (uint32_t)mem_len);
                g_tcc.tcc_delete(ctx); ctx = nullptr;

                uint32_t elf_total = 0;
                uint8_t* elf = wrap_elf32(code, (uint32_t)mem_len,
                                          entry_off, &elf_total);
                delete[] code;

                if (elf && elf_total) {
                    tcc_bc('W');
                    result = (fat32_write_file(out_filename, elf, elf_total) == 0)
                             ? 0 : TCC_ERR_OUTPUT;
                    delete[] elf;
                } else {
                    result = TCC_ERR_NOMEM;
                }
            } else {
                result = TCC_ERR_NOMEM;
            }
            if (ctx) { g_tcc.tcc_delete(ctx); ctx = nullptr; }
            g_tcc_busy = false;
            tcc_bc(result == 0 ? 'D' : 'F');
            return result;
        }
    }

    // ── Path B: tcc_output_file() → scratch on FAT32 ─────────────────
    g_tcc.tcc_set_output_type(ctx, TCC_OUTPUT_EXE);
    // Build a scratch name: "__" + out_filename (truncated to 62 chars)
    char scratch[68]; scratch[0]='_'; scratch[1]='_';
    int si = 2;
    for (int i = 0; out_filename[i] && si < 66; ++i) scratch[si++] = out_filename[i];
    scratch[si] = '\0';

    rc = g_tcc.tcc_output_file(ctx, scratch);
    g_tcc.tcc_delete(ctx); ctx = nullptr;

    if (rc == 0) {
        char* elf_raw = fat32_read_file_as_string(scratch);
        if (elf_raw) {
            // Derive ELF size from program headers.
            const Elf32_Ehdr* reh = (const Elf32_Ehdr*)elf_raw;
            uint32_t esz = sizeof(Elf32_Ehdr);
            if (reh->e_ident[0] == 0x7F) {
                for (uint16_t i = 0; i < reh->e_phnum; ++i) {
                    const Elf32_Phdr* rph = (const Elf32_Phdr*)
                        ((const uint8_t*)elf_raw
                         + reh->e_phoff + i * reh->e_phentsize);
                    uint32_t e2 = rph->p_offset + rph->p_filesz;
                    if (e2 > esz) esz = e2;
                }
                result = (fat32_write_file(out_filename, elf_raw, esz) == 0)
                         ? 0 : TCC_ERR_OUTPUT;
            }
            delete[] elf_raw;
        } else {
            result = TCC_ERR_OUTPUT;
        }
    } else {
        result = TCC_ERR_COMPILE;
    }

    g_tcc_busy = false;
    tcc_bc(result == 0 ? 'D' : 'F');
    return result;
}