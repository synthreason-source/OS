/* ====================================================================
 * bochs_cstubs.c — freestanding C stdlib shims for the kernel build.
 *
 * Compiled with -ffreestanding and NO system headers. Provides
 * minimal implementations of every libc symbol that libcpu.a,
 * libmemory.a, libcpudb.a, libfpu.a, libgcc_eh.a, or our bochs_infra
 * code references.
 *
 * Memory invariants enforced here:
 *
 *   M1. The bump allocator below backs every malloc/new in the kernel
 *       Bochs path. Capacity is 1 MiB — enough for:
 *
 *         - BX_MEM_C::init_memory() vector[]      (~1 MiB at our
 *           configured request size — but vector goes through
 *           alloc_vector_aligned which uses operator new in
 *           libmemory.a; that ends up here)
 *         - BX_MEM_C::init_memory() blocks[]      (8 entries x 4 B
 *           = 32 B at our 1 MiB guest size, but grows with guest size)
 *         - BX_MEM_C::init_memory() memory_handlers[] (up to ~1 M
 *           entries x 4 B = ~4 MiB on a 40-bit phys-addr config)
 *         - libgcc_eh's per-thread exception-handling globals
 *           (~256 B once)
 *         - bx_param_string_c dummies' backing buffers
 *
 *       The biggest single allocation is the memory_handlers table.
 *       For BX_PHY_ADDRESS_WIDTH = 32 (the common 32-bit-host case)
 *       it's (1<<32 >> 20) = 4096 entries = 16 KiB. For 40-bit phys
 *       addrs it's 4 MiB. The pool below is sized accordingly.
 *
 *   M2. Allocation is 8-byte aligned. malloc rounds up the requested
 *       size to a multiple of 8 before bumping the pointer. This
 *       matches the alignment requirements of any standard C/C++
 *       object on a 32-bit i386 build.
 *
 *   M3. Out-of-pool returns NULL (the previous version halted the
 *       CPU; that prevents the caller from gracefully degrading or
 *       reporting). Callers that need a hard failure can check.
 * ==================================================================== */

typedef unsigned long  size_t;
typedef long           ssize_t;
typedef long           time_t;
typedef long long      off64_t;
typedef int            pthread_mutex_t;

/* ── Bump allocator ─────────────────────────────────────────────────────── */
/* 8 MiB is enough for the worst-case memory_handlers table (4 MiB at
 * 40-bit phys addr config) plus a few MiB of slack for blocks, vector,
 * and miscellaneous small allocations. The pool lives in BSS so it
 * doesn't bloat the kernel ELF on disk. */

/* 48 MiB. Sized for the worst-case BX_MEM_C::init_memory request with
 * BX_PHY_ADDRESS_WIDTH = 40 (the 64-bit Bochs build):
 *
 *   vector[]          = host + 2 MiB BIOSROMSZ + 128 KiB EXROMSIZE + 4 KiB
 *                       = 16 MiB + ~2.1 MiB = ~18.2 MiB
 *   memory_handlers[] = (1 << 40) >> 20 entries * 4 B = 4 MiB
 *   blocks[]          = (16 MiB / 128 KiB) entries * 4 B = 512 B (negligible)
 *   misc small allocs (param strings, libgcc_eh) = a few KiB
 *
 * Total ≈ 22.5 MiB. 48 MiB is roughly 2× to leave room for the kernel
 * to also use this pool for its own allocations after Bochs init. The
 * BSS allocation cost is paid by GRUB zeroing it during multiboot
 * load; the on-disk kernel ELF is unaffected.
 *
 * Critical: previously 8 MiB. With that, vector[] allocation failed
 * silently (compiler optimised out the NULL check in
 * alloc_vector_aligned, since operator new in standard C++ doesn't
 * return NULL), causing rom = vector + host to dereference a NULL
 * base + 16 MiB offset and write 2.1 MiB of 0xFF garbage to physical
 * address 0x1000000 — sometimes wedging the boot inside the bogus
 * memset depending on what BSS was placed at that range.
 */
#define BHEAP_BYTES (48 * 1024 * 1024)
static char  _bheap[BHEAP_BYTES] __attribute__((aligned(16)));
static unsigned long _bptr = 0;

void* malloc(size_t n) {
    /* Round up to 8-byte alignment for any standard alignment
       requirement on i386. */
    n = (n + 7u) & ~(size_t)7u;
    if (_bptr + n > (unsigned long)BHEAP_BYTES) {
        return (void*)0;
    }
    void* p = _bheap + _bptr;
    _bptr += n;
    return p;
}

void free(void* p) { (void)p; }   /* bump allocator: no-op free */

/* ── Bump-pool fallback for the kernel's operator new ───────────────────
 * The Bochs constructors (e.g. icache.o's pageWriteStampTable ctor, which
 * allocates 4 MiB) call the global C++ operator new, which kernel.cpp
 * routes to its own FreeListAllocator. By the time `test` runs, that heap
 * is mostly consumed by the running desktop, so the 4 MiB request fails
 * and the kernel OOM-halts. This 48 MiB pool was sized specifically for
 * Bochs (see the header comment). These two helpers let kernel.cpp's
 * operator new fall back here instead of halting:
 *   bochs_pool_alloc(n)      — allocate n bytes from the pool (NULL if full)
 *   bochs_pool_owns(p)       — nonzero if p points inside the pool, so the
 *                              kernel's operator delete can skip it (the
 *                              bump allocator never frees individually). */
void* bochs_pool_alloc(size_t n) { return malloc(n); }

int bochs_pool_owns(const void* p) {
    const char* c = (const char*)p;
    return (c >= _bheap) && (c < _bheap + BHEAP_BYTES);
}

void abort(void) { __asm__("cli; hlt"); __builtin_unreachable(); }

/* ── String / memory functions ─────────────────────────────────────────── */
size_t strlen(const char* s)         { size_t n=0; while(s[n]) n++; return n; }
int    strcmp(const char* a, const char* b) {
    while(*a && *a==*b){a++;b++;} return (unsigned char)*a-(unsigned char)*b;
}
int    strncmp(const char* a, const char* b, size_t n) {
    while(n && *a && *a==*b){a++;b++;n--;}
    return n ? (unsigned char)*a-(unsigned char)*b : 0;
}
char*  strncpy(char* d, const char* s, size_t n) {
    size_t i=0;
    for(; i<n && s[i]; i++) d[i] = s[i];
    for(; i<n; i++) d[i] = 0;
    return d;
}
char*  strcat(char* d, const char* s) {
    char* r = d;
    while(*d) d++;
    while((*d++ = *s++));
    return r;
}
char*  strncat(char* d, const char* s, size_t n) {
    char* r = d;
    while(*d) d++;
    while(n-- && *s) *d++ = *s++;
    *d = 0;
    return r;
}
const char* strstr(const char* h, const char* n) {
    if(!*n) return h;
    for(; *h; h++) {
        const char *a = h, *b = n;
        while(*a && *b && *a == *b) { a++; b++; }
        if(!*b) return h;
    }
    return (const char*)0;
}
int    strcasecmp(const char* a, const char* b) {
    while(*a && (*a|32) == (*b|32)) { a++; b++; }
    return (*a|32) - (*b|32);
}
void*  memcpy(void* d, const void* s, size_t n) {
    char* dd = (char*)d; const char* ss = (const char*)s;
    while(n--) *dd++ = *ss++;
    return d;
}
void*  memset(void* d, int c, size_t n) {
    char* p = (char*)d;
    while(n--) *p++ = (char)c;
    return d;
}
void*  memmove(void* d, const void* s, size_t n) {
    char* dd = (char*)d; const char* ss = (const char*)s;
    if(dd < ss) { while(n--) *dd++ = *ss++; }
    else        { dd += n; ss += n; while(n--) *--dd = *--ss; }
    return d;
}
int    memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* p = (const unsigned char*)a;
    const unsigned char* q = (const unsigned char*)b;
    while(n--) { if(*p != *q) return *p - *q; p++; q++; }
    return 0;
}

/* ── _FORTIFY_SOURCE compatibility wrappers ────────────────────────────── */
/* Some glibc headers define these via macros when _FORTIFY_SOURCE is on.
   libcpu.a may have been compiled with that on. Provide harmless stubs. */
char* __strcpy_chk (char* d, const char* s, size_t dsz) {
    (void)dsz; char* r = d; while((*d++ = *s++)); return r;
}
char* __strncpy_chk(char* d, const char* s, size_t n, size_t dsz) {
    (void)dsz; return strncpy(d, s, n);
}
void* __memcpy_chk (void* d, const void* s, size_t n, size_t dsz) {
    (void)dsz; return memcpy(d, s, n);
}
void* __memset_chk (void* d, int c, size_t n, size_t dsz) {
    (void)dsz; return memset(d, c, n);
}
int __sprintf_chk  (char* b, int f, size_t dsz, const char* fmt, ...) {
    (void)f; (void)dsz; (void)fmt; if(b) *b=0; return 0;
}
int __snprintf_chk (char* b, size_t n, int f, size_t dsz, const char* fmt, ...) {
    (void)f; (void)dsz; (void)fmt; if(b && n) b[0]=0; return 0;
}
int __vsprintf_chk (char* b, int f, size_t dsz, const char* fmt, void* ap) {
    (void)f; (void)dsz; (void)fmt; (void)ap; if(b) *b=0; return 0;
}
int __fprintf_chk  (void* fp, int f, const char* fmt, ...) {
    (void)fp; (void)f; (void)fmt; return 0;
}
int __printf_chk   (int f, const char* fmt, ...) {
    (void)f; (void)fmt; return 0;
}
/* __stack_chk_fail / __stack_chk_guard are provided by fixes.h (-include). */
void __assert_fail(const char* a, const char* b, unsigned c, const char* d) {
    (void)a; (void)b; (void)c; (void)d;
    abort();
}

/* ── Math / random / time ──────────────────────────────────────────────── */
double pow(double a, double b) { (void)a; (void)b; return 0.0; }
time_t time(time_t* t)         { if(t) *t = 0; return 0; }
void   srand(unsigned s)       { (void)s; }
int    rand(void)              { return 42; }

/* ── pthreads (libgcc_eh's eh_globals.cc takes a mutex) ────────────────── */
int pthread_mutex_lock   (pthread_mutex_t* m)                  { (void)m; return 0; }
int pthread_mutex_unlock (pthread_mutex_t* m)                  { (void)m; return 0; }
int pthread_mutex_destroy(pthread_mutex_t* m)                  { (void)m; return 0; }
int pthread_mutex_init   (pthread_mutex_t* m, const void* a)   { (void)m; (void)a; return 0; }

/* ── Dynamic linker (libgcc_eh's frame-registration path queries this) ── */
int _dl_find_object(void* addr, void* result) {
    (void)addr; (void)result; return -1;
}

/* ── sscanf / strto* (some Bochs config-parsing code references these) ─ */
int                __isoc23_sscanf (const char* s, const char* f, ...)        { (void)s; (void)f; return 0; }
unsigned long long __isoc23_strtoull(const char* s, char** e, int b)          { (void)s; (void)e; (void)b; return 0; }
long               __isoc23_strtol  (const char* s, char** e, int b)          { (void)s; (void)e; (void)b; return 0; }
double             strtod           (const char* s, char** e)                 { (void)s; (void)e; return 0.0; }
int                snprintf         (char* b, size_t n, const char* f, ...)   { (void)n; (void)f; if(b && n) *b = 0; return 0; }

/* ── FILE stubs ─────────────────────────────────────────────────────────── */
typedef struct { int fd; } FILE;
static FILE _null_file = { -1 };
FILE*  fopen64    (const char* p, const char* m)        { (void)p; (void)m; return (FILE*)0; }
FILE*  tmpfile64  (void)                                { return (FILE*)0; }
int    fclose     (FILE* f)                             { (void)f; return 0; }
int    feof       (FILE* f)                             { (void)f; return 1; }
char*  fgets      (char* s, int n, FILE* f)             { (void)s; (void)n; (void)f; return (char*)0; }
int    fflush     (FILE* f)                             { (void)f; return 0; }
size_t fread      (void* p, size_t sz, size_t n, FILE* f) { (void)p; (void)sz; (void)n; (void)f; return 0; }
size_t fwrite     (const void* p, size_t sz, size_t n, FILE* f) { (void)p; (void)sz; (void)n; (void)f; return 0; }
int    fseeko64   (FILE* f, off64_t o, int w)           { (void)f; (void)o; (void)w; return -1; }
FILE*  stdout = &_null_file;
FILE*  stderr = &_null_file;
int    fprintf(FILE* f, const char* fmt, ...)           { (void)f; (void)fmt; return 0; }
int    fputs  (const char* s, FILE* f)                  { (void)s; (void)f; return 0; }

/* ── POSIX file operations ──────────────────────────────────────────────── */
int     open64 (const char* p, int f, ...)              { (void)p; (void)f; return -1; }
int     fstat64(int fd, void* st)                       { (void)fd; (void)st; return -1; }
ssize_t read   (int fd, void* buf, size_t n)            { (void)fd; (void)buf; (void)n; return -1; }
int     close  (int fd)                                 { (void)fd; return 0; }

/* ── Bochs-specific globals ─────────────────────────────────────────────── */
int simulate_xapic = 0;

/* _setjmp / longjmp / __longjmp_chk are provided by setjmp.S (pure asm
 * matching glibc's i386 jmp_buf layout). libcpu.a's internal exception-
 * unwinding bookkeeping calls these even though we never throw. */
