// =============================================================================
// tcc_kernel.cpp — in-kernel TCC C compiler
// =============================================================================
//
// Replaces tcc_stub.cpp. Links i386-libtcc-kern.a (TCC compiled targeting
// i386) into the kernel binary. Provides every POSIX symbol libtcc.a needs
// via kernel-heap-backed stubs, and implements tcc_kernel_cmd_cc() which the
// shell calls when the user types `cc foo.c`.
//
// Pipeline for  `cc foo.c`  typed in the kernel shell:
//   1. fat32_read_file_as_string("foo.c")      — source bytes from disk
//   2. tcc_new() / tcc_compile_string()        — parse + codegen (i386 ELF)
//   3. tcc_output_file("/@tcc/out.elf")        — ELF written via fake fd shim
//      (open/fdopen/fwrite intercept write into kernel-heap buffer)
//   4. fat32_write_file(out_name, buf, size)   — persist ELF to FAT32
//   5. load_and_execute_elf(out_name, …)       — launch in Bochs CPU slot
//
// Symbols provided here (all in extern "C" so TCC's C-linkage resolves):
//   heap:    malloc, realloc, free, calloc
//   string:  strdup, strtol/ll/ul/ull, strtod/f/ld, ldexpl, strerror, qsort
//   glibc:   __isoc23_strtol/ll/ul/ull, __stack_chk_fail
//   stdio:   vsnprintf, sprintf, vsprintf, fprintf, vfprintf, fwrite, fputc,
//            fputs, fflush, putchar, puts, stdout, stderr, stdin
//   file:    open, read, lseek, close, fopen, fdopen, fclose, freopen, unlink
//   env:     getcwd, realpath, environ, __errno_location
//   time:    time, localtime
//   stubs:   mprotect, dlopen/dlclose/dlsym, sigaction/sigaddset/sigemptyset/
//            sigprocmask, sysconf, exit, abort
// =============================================================================


// ── Forward-declare kernel functions (defined in kernel.cpp) ─────────────────
// (TerminalWindow is opaque here — accessed only via tcc_bridge_exec_elf)

// Bridge functions defined at the bottom of kernel.cpp with extern "C" linkage.
extern "C" {
    void  tcc_bridge_console_print(const char* s);
    char* tcc_bridge_fat32_read   (const char* filename);
    int   tcc_bridge_fat32_write  (const char* filename, const void* data,
                                   unsigned int size);
    int   tcc_bridge_exec_elf     (void* terminal, const char* filename,
                                   const char* args);
}

// Convenience macros so the rest of tcc_kernel.cpp reads naturally
#define console_print(s)              tcc_bridge_console_print(s)
#define fat32_read_file_as_string(f)  tcc_bridge_fat32_read(f)
#define fat32_write_file(f,d,s)       tcc_bridge_fat32_write(f,d,s)

// TerminalWindow is opaque here — we call it via tcc_bridge_exec_elf

// ── Kernel heap via operator new/delete (defined in kernel.cpp) ──────────────
// We provide malloc/free/realloc in extern "C" below.

// ── va_list helpers — compiler-builtin, no system header needed ──────────────
// GCC's __builtin_va_* work in freestanding mode.
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap)         __builtin_va_end(ap)
#define va_arg(ap, type)   __builtin_va_arg(ap, type)
#define va_copy(d, s)      __builtin_va_copy(d, s)

// ── All stubs in extern "C" ───────────────────────────────────────────────────
extern "C" {

// ── String functions — defined HERE so i386-libtcc-kern.a resolves them ───────
// kernel.cpp defines these too, but with --allow-multiple-definition the
// linker picks the first definition. Defining them in tcc_kernel.cpp ensures
// they appear in the same object that i386-libtcc-kern.a references directly.
unsigned long strlen(const char* s) {
    unsigned long n = 0; while (s[n]) n++; return n;
}
int strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *(const unsigned char*)a - *(const unsigned char*)b;
}
int strncmp(const char* a, const char* b, unsigned long n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (*(const unsigned char*)a - *(const unsigned char*)b) : 0;
}
char* strcpy(char* d, const char* s) {
    char* r = d; while ((*d++ = *s++)); return r;
}
char* strncpy(char* d, const char* s, unsigned long n) {
    unsigned long i = 0;
    while (i < n && s[i]) { d[i] = s[i]; i++; }
    while (i < n) d[i++] = '\0';
    return d;
}
char* strcat(char* d, const char* s) {
    char* r = d; while (*d) d++; while ((*d++ = *s++)); return r;
}
char* strchr(const char* s, int c) {
    while (*s && *s != (char)c) s++;
    return (*s == (char)c) ? (char*)s : nullptr;
}
char* strrchr(const char* s, int c) {
    const char* last = nullptr;
    do { if (*s == (char)c) last = s; } while (*s++);
    return (char*)last;
}
const char* strstr(const char* h, const char* n) {
    if (!*n) return h;
    for (; *h; h++) {
        if (*h == *n) {
            const char* a = h; const char* b = n;
            while (*b && *a == *b) { a++; b++; }
            if (!*b) return h;
        }
    }
    return nullptr;
}
char* strstr_w(const char* h, const char* n) { return (char*)strstr(h,n); }

// memcpy, memset, memmove, memcmp — needed by i386-libtcc-kern.a
void* memcpy(void* d, const void* s, unsigned long n) {
    unsigned char* dd=(unsigned char*)d;
    const unsigned char* ss=(const unsigned char*)s;
    for (unsigned long i=0;i<n;i++) dd[i]=ss[i];
    return d;
}
void* memset(void* d, int v, unsigned long n) {
    unsigned char* dd=(unsigned char*)d;
    for (unsigned long i=0;i<n;i++) dd[i]=(unsigned char)v;
    return d;
}
void* memmove(void* d, const void* s, unsigned long n) {
    unsigned char* dd=(unsigned char*)d;
    const unsigned char* ss=(const unsigned char*)s;
    if (dd < ss) { for (unsigned long i=0;i<n;i++) dd[i]=ss[i]; }
    else         { for (unsigned long i=n;i>0;i--) dd[i-1]=ss[i-1]; }
    return d;
}
int memcmp(const void* a, const void* b, unsigned long n) {
    const unsigned char* p=(const unsigned char*)a;
    const unsigned char* q=(const unsigned char*)b;
    for (unsigned long i=0;i<n;i++) if(p[i]!=q[i]) return (int)p[i]-(int)q[i];
    return 0;
}

// printf — routes to console_print; kern_vsnprintf defined later, forward-declared here
static int kern_vsnprintf(char* buf, unsigned long cap, const char* fmt, va_list ap);

void printf(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    kern_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    console_print(buf);
}
int snprintf(char* buf, unsigned long cap, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = kern_vsnprintf(buf, cap, fmt, ap);
    va_end(ap); return r;
}

// ── Memory allocation ─────────────────────────────────────────────────────────
// IMPORTANT: this calls kernel_alloc_nofail()/kernel_free() (defined in
// kernel.cpp), NOT ::operator new/delete directly. The global operator new
// halts the entire kernel on exhaustion (oom_halt()) — appropriate for
// kernel-internal structures, but not for memory driven by an arbitrary
// user-supplied C source file. A bad `cc foo.c` should report "out of
// memory" and return to the shell, not freeze the OS.
extern void* kernel_alloc_nofail(unsigned long size);
extern void  kernel_free(void* ptr);

// Set the moment any malloc() call fails during this compile. TCC's own
// error path may report a confusing/unrelated parse or codegen error when
// the real cause was a failed allocation deep inside libtcc — checking
// this latch lets tcc_kernel_cmd_cc() print an unambiguous "out of memory"
// message instead. Reset at the top of every tcc_kernel_cmd_cc() call.
static bool g_oom_hit = false;

void* malloc(unsigned long size) {
    if (!size) return nullptr;
    void* p = kernel_alloc_nofail(size);
    if (!p) g_oom_hit = true;
    return p;
}
void free(void* ptr) {
    if (ptr) kernel_free(ptr);
}
extern unsigned long kernel_alloc_usable_size(void* ptr);

void* realloc(void* ptr, unsigned long size) {
    if (!ptr)  return malloc(size);
    if (!size) { free(ptr); return nullptr; }
    void* n = malloc(size);
    if (n) {
        // Copy only as many bytes as the OLD allocation actually has.
        // Copying `size` (the NEW, larger request) unconditionally would
        // read past the end of the original block on every grow — an
        // out-of-bounds read that silently corrupts whatever heap memory
        // follows it. kernel_alloc_usable_size() gives a safe upper bound;
        // fall back to `size` only if it's unavailable (e.g. bump-pool
        // pointer), which preserves the old (unsafe but pre-existing)
        // behavior solely for that rare path.
        unsigned long old_usable = kernel_alloc_usable_size(ptr);
        unsigned long copy_n = old_usable ? old_usable : size;
        if (copy_n > size) copy_n = size;
        memcpy(n, ptr, copy_n);
        free(ptr);
    }
    return n;
}
void* calloc(unsigned long n, unsigned long size) {
    if (n != 0 && size > (~0UL) / n) return nullptr;  // overflow guard
    unsigned long t = n * size;
    void* p = malloc(t);
    if (p) memset(p, 0, t);
    return p;
}

// ── String utilities ──────────────────────────────────────────────────────────
char* strdup(const char* s) {
    if (!s) return nullptr;
    unsigned long n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static long long kern_strtoll(const char* s, char** end, int base) {
    while (*s == ' ' || *s == '\t') s++;
    int neg = 0;
    if (*s == '-')      { neg = 1; s++; }
    else if (*s == '+') { s++; }
    if (base == 0) {
        if (s[0]=='0' && (s[1]=='x'||s[1]=='X')) { base=16; s+=2; }
        else if (s[0]=='0')                        { base=8;  s++;  }
        else                                        { base=10;       }
    } else if (base==16 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) { s+=2; }
    long long v = 0;
    while (1) {
        int d;
        if      (*s>='0'&&*s<='9') d = *s-'0';
        else if (*s>='a'&&*s<='f') d = *s-'a'+10;
        else if (*s>='A'&&*s<='F') d = *s-'A'+10;
        else break;
        if (d >= base) break;
        v = v * base + d;
        s++;
    }
    if (end) *end = (char*)s;
    return neg ? -v : v;
}
long          strtol  (const char* s, char** e, int b) { return (long)kern_strtoll(s,e,b); }
long long     strtoll (const char* s, char** e, int b) { return       kern_strtoll(s,e,b); }
unsigned long strtoul (const char* s, char** e, int b) { return (unsigned long)      kern_strtoll(s,e,b); }
unsigned long long strtoull(const char* s, char** e, int b) { return (unsigned long long)kern_strtoll(s,e,b); }
long          __isoc23_strtol  (const char* s, char** e, int b) { return strtol  (s,e,b); }
long long     __isoc23_strtoll (const char* s, char** e, int b) { return strtoll (s,e,b); }
unsigned long __isoc23_strtoul (const char* s, char** e, int b) { return strtoul (s,e,b); }
unsigned long long __isoc23_strtoull(const char* s, char** e, int b) { return strtoull(s,e,b); }

double strtod(const char* s, char** e) {
    while (*s==' '||*s=='\t') s++;
    int neg = (*s=='-') ? (s++,1) : (*s=='+'?(s++,0):0);
    double v = 0;
    while (*s>='0'&&*s<='9') v = v*10+(*s++-'0');
    if (*s=='.') { s++; double f=0.1; while(*s>='0'&&*s<='9'){v+=(*s++-'0')*f;f*=0.1;} }
    if (*s=='e'||*s=='E') {
        s++; int en=(*s=='-')?(s++,1):(*s=='+'?(s++,0):0);
        int ex=0; while(*s>='0'&&*s<='9') ex=ex*10+(*s++-'0');
        double m=1; while(ex-->0) m*=10;
        v = en ? v/m : v*m;
    }
    if (e) *e=(char*)s;
    return neg?-v:v;
}
float       strtof (const char* s, char** e) { return (float)strtod(s,e); }
long double strtold(const char* s, char** e) { return (long double)strtod(s,e); }

long double ldexpl(long double x, int exp) {
    if (exp>=0) { while(exp-->0) x*=2.0L; }
    else        { while(exp++<0) x*=0.5L; }
    return x;
}

const char* strerror(int e) {
    switch (e) {
        case 0:  return "Success";
        case 1:  return "EPERM";
        case 2:  return "ENOENT";
        case 5:  return "EIO";
        case 9:  return "EBADF";
        case 12: return "ENOMEM";
        case 13: return "EACCES";
        case 22: return "EINVAL";
        case 28: return "ENOSPC";
        default: return "Unknown error";
    }
}

// qsort — insertion sort (TCC only sorts small symbol tables)
void qsort(void* base, unsigned long n, unsigned long sz,
           int (*cmp)(const void*, const void*)) {
    char* b = (char*)base;
    char* tmp = (char*)malloc(sz);
    if (!tmp) return;
    for (unsigned long i=1; i<n; i++) {
        memcpy(tmp, b+i*sz, sz);
        long j = (long)i-1;
        while (j>=0 && cmp(b+(unsigned long)j*sz, tmp)>0) {
            memcpy(b+(unsigned long)(j+1)*sz, b+(unsigned long)j*sz, sz);
            j--;
        }
        memcpy(b+(unsigned long)(j+1)*sz, tmp, sz);
    }
    free(tmp);
}

// ── vsnprintf — used by TCC for error messages and path formatting ─────────────
static int kern_vsnprintf(char* buf, unsigned long cap,
                          const char* fmt, va_list ap) {
    if (!buf || !cap) return 0;
    char* out  = buf;
    char* end  = buf + cap - 1;

    while (*fmt && out < end) {
        if (*fmt != '%') { *out++ = *fmt++; continue; }
        fmt++; // skip '%'

        // Flags
        int leftj=0, zero=0, plus=0;
        while (*fmt=='-'||*fmt=='0'||*fmt=='+') {
            if (*fmt=='-') leftj=1;
            if (*fmt=='0') zero=1;
            if (*fmt=='+') plus=1;
            fmt++;
        }
        // Width
        int width=0;
        while (*fmt>='0'&&*fmt<='9') width=width*10+(*fmt++-'0');
        // Precision
        int prec=-1;
        if (*fmt=='.') { fmt++; prec=0; while(*fmt>='0'&&*fmt<='9') prec=prec*10+(*fmt++-'0'); }
        // Length modifier
        int lng=0;
        if (*fmt=='l') { lng=1; fmt++; if(*fmt=='l'){lng=2;fmt++;} }
        else if (*fmt=='z'||*fmt=='t') { lng=1; fmt++; }

        char spec = *fmt++;
        if (spec=='%') { *out++='%'; continue; }
        if (spec=='c') { *out++=(char)va_arg(ap,int); continue; }

        if (spec=='s') {
            const char* sv = va_arg(ap,const char*);
            if (!sv) sv="(null)";
            int slen=0; while(sv[slen]&&(prec<0||slen<prec)) slen++;
            if (!leftj) for(int k=slen;k<width&&out<end;k++) *out++=' ';
            for(int k=0;k<slen&&out<end;k++) *out++=sv[k];
            if ( leftj) for(int k=slen;k<width&&out<end;k++) *out++=' ';
            continue;
        }

        // Integer
        unsigned long long uval=0; int isneg=0;
        if (spec=='d'||spec=='i') {
            long long sv2 = (lng==2)?va_arg(ap,long long):
                            (lng==1)?(long long)va_arg(ap,long):
                            (long long)va_arg(ap,int);
            if (sv2<0){isneg=1;uval=(unsigned long long)(-sv2);}
            else uval=(unsigned long long)sv2;
        } else if (spec=='u'||spec=='x'||spec=='X'||spec=='o') {
            uval=(lng==2)?va_arg(ap,unsigned long long):
                 (lng==1)?(unsigned long long)va_arg(ap,unsigned long):
                 (unsigned long long)va_arg(ap,unsigned int);
        } else if (spec=='p') {
            uval=(unsigned long long)(unsigned long)va_arg(ap,void*);
            spec='x';
        } else { continue; } // unknown spec

        const char* hex=(spec=='X')?"0123456789ABCDEF":"0123456789abcdef";
        int base=(spec=='x'||spec=='X')?16:(spec=='o'?8:10);
        char num[32]; int ni=0;
        if (!uval) num[ni++]='0';
        unsigned long long tmp2=uval;
        while(tmp2){num[ni++]=hex[tmp2%base];tmp2/=base;}
        if(isneg)num[ni++]='-'; else if(plus)num[ni++]='+';

        int pad=width-ni;
        if(!leftj&&!zero&&pad>0) for(int k=0;k<pad&&out<end;k++) *out++=' ';
        if(!leftj&& zero&&pad>0) {
            // sign first, then zeros
            if(isneg){*out++='-';ni--;if(out>=end)break;}
            else if(plus){*out++='+';ni--;if(out>=end)break;}
            for(int k=0;k<pad&&out<end;k++) *out++='0';
        }
        for(int k=ni-1;k>=0&&out<end;k--) *out++=num[k];
        if(leftj&&pad>0) for(int k=0;k<pad&&out<end;k++) *out++=' ';
    }
    *out='\0';
    return (int)(out-buf);
}

int vsnprintf(char* buf, unsigned long cap, const char* fmt, va_list ap) {
    return kern_vsnprintf(buf, cap, fmt, ap);
}
int sprintf(char* buf, const char* fmt, ...) {
    va_list ap; va_start(ap,fmt); int r=kern_vsnprintf(buf,65536,fmt,ap); va_end(ap); return r;
}
int vsprintf(char* buf, const char* fmt, va_list ap) {
    return kern_vsnprintf(buf,65536,fmt,ap);
}

// ── errno ─────────────────────────────────────────────────────────────────────
static int g_errno_val = 0;
int* __errno_location(void) { return &g_errno_val; }

// ── Time / environment ────────────────────────────────────────────────────────
typedef long tcc_time_t;
struct tcc_tm { int tm_sec,tm_min,tm_hour,tm_mday,tm_mon,tm_year,
                    tm_wday,tm_yday,tm_isdst; };

tcc_time_t time(tcc_time_t* t)       { if(t)*t=0; return 0; }
struct tcc_tm* localtime(const tcc_time_t*) {
    static struct tcc_tm z={};
    return &z;
}

char* environ_arr[] = { nullptr };
char** environ = environ_arr;

char* getcwd(char* buf, unsigned long size) {
    if (!buf || size<2) return nullptr;
    buf[0]='/'; buf[1]='\0'; return buf;
}
char* realpath(const char* path, char* resolved) {
    if (!resolved) resolved=(char*)malloc(256);
    if (!resolved) return nullptr;
    unsigned long n=strlen(path); if(n>255)n=255;
    memcpy(resolved,path,n); resolved[n]='\0';
    return resolved;
}

// ── Stubs for runtime-only symbols (tccrun.c dead code) ──────────────────────
int mprotect(void*, unsigned long, int) { return 0; }

struct kern_sigaction { void(*handler)(int); unsigned long flags; };
typedef unsigned long kern_sigset_t;
int sigaction  (int, const struct kern_sigaction*, struct kern_sigaction*) { return 0; }
int sigaddset  (kern_sigset_t* s, int)   { (void)s; return 0; }
int sigemptyset(kern_sigset_t* s)        { if(s)*s=0; return 0; }
int sigprocmask(int, const kern_sigset_t*, kern_sigset_t*) { return 0; }

void* dlopen (const char*, int)  { return nullptr; }
void* dlsym  (void*, const char*){ return nullptr; }
int   dlclose(void*)             { return 0; }

long sysconf(int) { return 4096; }

void exit(int code) {
    (void)code;
    console_print("tcc_kernel: exit() called\n");
    for(;;) {}
}
void abort(void) { exit(1); }

void __stack_chk_fail(void) {
    console_print("tcc_kernel: stack smash!\n");
    for(;;) {}
}

// ── RAM-backed fd/FILE shim ───────────────────────────────────────────────────
#define FAKE_FD_BASE  500
#define FAKE_FD_MAX   16   // TCC opens several internal fds during compilation

// Hard ceiling on any single fake-fd output buffer. A 32-bit i386 ELF
// produced by a single `cc` invocation has no legitimate reason to exceed
// this. Without a cap, a runaway/corrupt compile would let
// kfd_write_bytes() double its buffer (65536 -> 128K -> 256K -> ...) until
// it had eaten the entire 64MB kernel heap and tripped the global
// allocator's OOM halt, freezing the whole OS over one bad `cc`.
#define TCC_FD_MAX_BYTES (16u * 1024u * 1024u)  // 16MB per fake-fd buffer

struct KFd {
    bool          active;
    bool          is_write;
    unsigned char* buf;
    unsigned long  cap;
    unsigned long  size;
    unsigned long  pos;
};

static KFd g_kfds[FAKE_FD_MAX];

static int kfd_alloc() {
    for (int i=0;i<FAKE_FD_MAX;i++)
        if (!g_kfds[i].active) {
            KFd* f = &g_kfds[i]; *f = {};
            f->active=true; return FAKE_FD_BASE+i;
        }
    return -1;
}
static KFd* kfd_get(int fd) {
    int i=fd-FAKE_FD_BASE;
    if (i<0||i>=FAKE_FD_MAX||!g_kfds[i].active) return nullptr;
    return &g_kfds[i];
}
static void kfd_release(int fd) {
    KFd* f=kfd_get(fd);
    if (f) { if(f->buf) free(f->buf); *f={}; }
}

// Free every fake-fd slot's buffer, active or not. Must be called at the
// START of every `cc` invocation (before tcc_new()) so that any buffer
// left behind by a previous failed/aborted compile — e.g. a compile that
// errored out after open() but before harvest_elf() ran — is released
// instead of silently accumulating. Without this sweep, repeated `cc`
// attempts on a broken source file leak ~64KB+ of kernel heap per attempt
// and never get it back: a slow, easy-to-trigger memory loop.
static void kfd_reset_all() {
    for (int i=0;i<FAKE_FD_MAX;i++) {
        KFd* f=&g_kfds[i];
        if (f->buf) { free(f->buf); }
        *f = {};
    }
}

#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT    0x40
#define O_TRUNC    0x200
#define O_BINARY   0

int open(const char* path, int flags, ...) {
    bool writing=(flags&O_WRONLY)||(flags&O_RDWR)||(flags&O_CREAT);
    { char _db[128]; snprintf(_db,sizeof(_db),"[tcc] open(%s, flags=0x%x, writing=%d)\n", path?path:"null", flags, (int)writing); console_print(_db); }

    if (!writing) {
        // FIX (#include "x.h" never found): this used to unconditionally
        // return ENOENT for every read-mode open(). That was harmless for
        // the main translation unit — tcc_kernel_cmd_cc() feeds that in
        // directly via fat32_read_file_as_string() + tcc_compile_string(),
        // never through open() — but libtcc's PREPROCESSOR resolves every
        // #include by calling this same open()/read()/close() path itself.
        // With read-mode open() always failing, #include "x.h" (and any
        // other local header) could never be found, no matter what was
        // actually on disk.
        //
        // Fix: load the requested file from FAT32 the same way the main
        // source file is loaded, and hand back a read-only fake fd over
        // its bytes so the existing read()/lseek()/close() shims below
        // (which already handle the read side generically) just work.
        char* data = fat32_read_file_as_string(path);
        if (!data) {
            g_errno_val=2;
            { char _db[160]; snprintf(_db,sizeof(_db),"[tcc] open(%s): ENOENT (not on disk)\n", path?path:"null"); console_print(_db); }
            return -1;
        }
        int fd=kfd_alloc();
        if (fd<0) {
            free(data);
            g_errno_val=12; console_print("[tcc] open: no fd slots!\n"); return -1;
        }
        KFd* f=kfd_get(fd);
        f->is_write=false;
        f->buf=(unsigned char*)data;              // owned by kfd now; freed on kfd_release/reset
        f->size=(unsigned long)strlen(data);
        f->cap=f->size;
        f->pos=0;
        { char _db[96]; snprintf(_db,sizeof(_db),"[tcc] open(%s): read fd=%d size=%lu\n", path?path:"null", fd, f->size); console_print(_db); }
        return fd;
    }

    int fd=kfd_alloc();
    if (fd<0) { g_errno_val=12; console_print("[tcc] open: no fd slots!\n"); return -1; }
    KFd* f=kfd_get(fd);
    f->is_write=true;
    f->cap=65536;
    f->buf=(unsigned char*)malloc(f->cap);
    if (!f->buf) { kfd_release(fd); g_errno_val=12; console_print("[tcc] open: malloc fail\n"); return -1; }
    { char _db[64]; snprintf(_db,sizeof(_db),"[tcc] open: allocated fd=%d\n",fd); console_print(_db); }
    return fd;
}

int close(int fd) {
    KFd* f=kfd_get(fd);
    if (!f) { g_errno_val=9; return -1; }
    { char _db[64]; snprintf(_db,sizeof(_db),"[tcc] close(fd=%d) size=%lu\n",fd,f->size); console_print(_db); }
    f->active=false; // keep buf alive for harvest (write) or explicit free (read)
    return 0;
}

long lseek(int fd, long off, int whence) {
    KFd* f=kfd_get(fd);
    if (!f) { g_errno_val=9; return -1; }
    unsigned long np;
    if      (whence==0) np=(unsigned long)off;
    else if (whence==1) np=f->pos+(unsigned long)off;
    else                np=f->size+(unsigned long)off;
    f->pos=np; return (long)np;
}

long read(int fd, void* buf, unsigned long n) {
    KFd* f=kfd_get(fd);
    if (!f||f->is_write) { g_errno_val=9; return -1; }
    unsigned long av=(f->pos<f->size)?(f->size-f->pos):0;
    unsigned long rd=(n<av)?n:av;
    memcpy(buf,f->buf+f->pos,rd);
    f->pos+=rd; return (long)rd;
}

static bool kfd_write_bytes(KFd* f, const void* data, unsigned long n) {
    { char _db[80]; snprintf(_db,sizeof(_db),"[tcc] kfd_write_bytes n=%lu cur_size=%lu\n",n,f->size); console_print(_db); }

    // Overflow guard: size + n wrapping around would otherwise look like
    // "no growth needed" and corrupt memory via a too-small buffer.
    unsigned long need = f->size + n;
    if (need < f->size) { g_errno_val=12; console_print("[tcc] kfd_write_bytes: size overflow\n"); return false; }

    // Hard cap: refuse to grow past TCC_FD_MAX_BYTES rather than doubling
    // forever and starving the rest of the kernel heap.
    if (need > TCC_FD_MAX_BYTES) {
        g_errno_val=12;
        console_print("[tcc] kfd_write_bytes: output exceeds cap, aborting\n");
        return false;
    }

    if (need>f->cap) {
        unsigned long nc=f->cap ? f->cap : 4096;
        while (nc<need) {
            unsigned long doubled = nc*2;
            if (doubled <= nc) { nc = need; break; }   // overflow guard on *2
            nc = doubled;
        }
        if (nc > TCC_FD_MAX_BYTES) nc = TCC_FD_MAX_BYTES;
        unsigned char* nb=(unsigned char*)malloc(nc);
        if (!nb) { g_errno_val=12; return false; }
        memcpy(nb,f->buf,f->size); free(f->buf);
        f->buf=nb; f->cap=nc;
    }
    memcpy(f->buf+f->size,data,n);
    f->size+=n; return true;
}

// ── write() syscall ───────────────────────────────────────────────────────────
// tcc_output_file (mob branch) calls write(fd,...) directly rather than fwrite.
// Without this stub, all bytes are silently dropped and harvest_elf sees size=0.
long write(int fd, const void* buf, unsigned long n) {
    KFd* f = kfd_get(fd);
    if (!f || !f->is_write) { g_errno_val = 9; return -1; }
    return kfd_write_bytes(f, buf, n) ? (long)n : -1;
}

// ── FILE* shim ────────────────────────────────────────────────────────────────
// IMPORTANT: libtcc.a was compiled against glibc's <stdio.h>, so inside that
// .a the symbol "FILE" is glibc's struct _IO_FILE (~148 bytes, 32-bit).
// We must NOT typedef our own struct as FILE — libtcc would try to dereference
// our small token as a glibc FILE and read garbage offsets, silently dropping
// all fwrite calls.
//
// The correct approach: declare our token struct under a different name and
// expose FILE* as an opaque pointer (forward-declared, never defined here).
// All stdio functions (fwrite, fputc, fclose, ...) are resolved at kernel
// link time from THIS translation unit, so libtcc.a never actually
// dereferences the FILE* it receives — it only passes it back to us.
// We embed the real fd number inside the token and recover it via a cast.

struct KFile {
    unsigned int magic;   // 0xF11EF11E — sanity check
    bool is_console;
    int  fd;
};

#define KFILE_MAGIC 0xF11EF11Eu
#define KFILE_MAX 16
static KFile g_kfiles[KFILE_MAX];

static KFile g_stdout_kf = {KFILE_MAGIC, true,  -1};
static KFile g_stderr_kf = {KFILE_MAGIC, true,  -1};

// FILE is declared as an incomplete struct so we can have FILE* without
// defining the layout — we cast KFile* to FILE* and back.
struct _KFileOpaque;
typedef struct _KFileOpaque FILE;

FILE* stdout = (FILE*)&g_stdout_kf;
FILE* stderr = (FILE*)&g_stderr_kf;
FILE* stdin  = nullptr;

static KFile* kf_of(FILE* f) {
    KFile* k = (KFile*)f;
    if (!k || k->magic != KFILE_MAGIC) return nullptr;
    return k;
}

static FILE* kfile_alloc(bool console, int fd) {
    for (int i = 0; i < KFILE_MAX; i++) {
        if (g_kfiles[i].magic != KFILE_MAGIC) {
            g_kfiles[i] = {KFILE_MAGIC, console, fd};
            return (FILE*)&g_kfiles[i];
        }
    }
    return nullptr;
}
static void kfile_free(FILE* f) {
    KFile* k = kf_of(f);
    if (!k || f == stdout || f == stderr) return;
    k->magic = 0;
}

FILE* fdopen(int fd, const char* mode) {
    { char _db[64]; snprintf(_db,sizeof(_db),"[tcc] fdopen(fd=%d)\n",fd); console_print(_db); }
    if (!kfd_get(fd)) { g_errno_val = 9; console_print("[tcc] fdopen: kfd_get FAILED\n"); return nullptr; }
    FILE* ret = kfile_alloc(false, fd);
    { char _db[80]; snprintf(_db,sizeof(_db),"[tcc] fdopen: KFile slot=%p\n",(void*)ret); console_print(_db); }
    return ret;
}
FILE* fopen(const char* path, const char* mode) {
    bool w = (mode && (mode[0] == 'w' || mode[0] == 'a'));
    int fd = open(path, w ? (O_WRONLY|O_CREAT|O_TRUNC) : O_RDONLY);
    if (fd < 0) return nullptr;
    return fdopen(fd, mode);
}
FILE* freopen(const char* path, const char* mode, FILE* /*f*/) {
    return fopen(path, mode);
}
int fclose(FILE* f) {
    KFile* k = kf_of(f);
    if (!k) return 0;
    if (f == stdout || f == stderr) return 0;
    int fd = k->fd;
    kfile_free(f);
    return close(fd);
}

static void con_write(const char* p, unsigned long n) {
    char tmp[128];
    while (n > 0) {
        unsigned long c = (n > 127) ? 127 : n;
        memcpy(tmp, p, c); tmp[c] = '\0';
        console_print(tmp); p += c; n -= c;
    }
}

unsigned long fwrite(const void* ptr, unsigned long sz,
                     unsigned long count, FILE* f) {
    if (!f) { console_print("[tcc] fwrite: NULL FILE*\n"); return 0; }
    unsigned long n = sz * count;
    KFile* k = kf_of(f);
    if (!k) { char _db[80]; snprintf(_db,sizeof(_db),"[tcc] fwrite: kf_of FAILED f=%p\n",(void*)f); console_print(_db); return 0; }
    if (k->is_console) { con_write((const char*)ptr, n); return count; }
    KFd* kf = kfd_get(k->fd);
    if (!kf) { char _db[80]; snprintf(_db,sizeof(_db),"[tcc] fwrite: kfd_get(%d) FAILED\n",k->fd); console_print(_db); return 0; }
    return kfd_write_bytes(kf, ptr, n) ? count : 0;
}

int fputc(int c, FILE* f) {
    char ch = (char)c;
    return (fwrite(&ch, 1, 1, f) == 1) ? (unsigned char)c : -1;
}
int fputs(const char* s, FILE* f) {
    unsigned long n = strlen(s);
    return (fwrite(s, 1, n, f) == n) ? (int)n : -1;
}
int fflush(FILE*) { return 0; }
int fprintf(FILE* f, const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = kern_vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    fwrite(buf, 1, (unsigned long)n, f); return n;
}
int vfprintf(FILE* f, const char* fmt, va_list ap) {
    char buf[512];
    int n = kern_vsnprintf(buf, sizeof(buf), fmt, ap);
    fwrite(buf, 1, (unsigned long)n, f); return n;
}
int putchar(int c) { return fputc(c, stdout); }
int puts(const char* s) { fputs(s, stdout); fputc('\n', stdout); return 0; }

int unlink(const char*) { return 0; }

} // extern "C"

// ── Include libtcc.h (symbols provided by i386-libtcc-kern.a at link time) ───
extern "C" {
#include "libtcc.h"
}

// ── Error callback ────────────────────────────────────────────────────────────
static char  g_errbuf[2048];
static int   g_errlen = 0;

static void tcc_err_cb(void*, const char* msg) {
    int ml=0; while(msg[ml]) ml++;
    int av=(int)sizeof(g_errbuf)-g_errlen-2;
    if (av>0) {
        int cp=(ml<av)?ml:av;
        memcpy(g_errbuf+g_errlen,msg,(unsigned long)cp);
        g_errlen+=cp;
        g_errbuf[g_errlen++]='\n';
        g_errbuf[g_errlen]='\0';
    }
    console_print(msg); console_print("\n");
}

// ── Harvest ELF from the closed fake fd ──────────────────────────────────────
static unsigned char* harvest_elf(unsigned long* sz) {
    console_print("[tcc] harvest_elf: scanning slots\n");
    for (int i=0;i<FAKE_FD_MAX;i++) {
        KFd* f=&g_kfds[i];
        { char _db[96]; snprintf(_db,sizeof(_db),"[tcc]   slot[%d]: active=%d write=%d buf=%p size=%lu\n", i,(int)f->active,(int)f->is_write,(void*)f->buf,f->size); console_print(_db); }
        if (!f->active && f->is_write && f->buf && f->size>0) {
            unsigned char* b=f->buf; *sz=f->size;
            f->buf=nullptr; f->size=0; return b;
        }
    }
    return nullptr;
}

// ── tcc_realloc wrapper (plain function, not lambda) ─────────────────────────
static void* tcc_kern_realloc(void* ptr, unsigned long size) {
    if (!size) { if(ptr) free(ptr); return nullptr; }
    if (!ptr)  return malloc(size);
    return realloc(ptr,size);
}

// ── tcc_kernel_version ────────────────────────────────────────────────────────
extern "C" int tcc_kernel_version(void) { return 2; } // 2 = real in-kernel TCC

// ── tcc_kernel_cmd_cc ─────────────────────────────────────────────────────────
extern "C" void tcc_kernel_cmd_cc(void* terminal_opaque,
                                  const char* src_name,
                                  const char* out_name_arg) {
    g_errlen = 0; g_errbuf[0] = '\0';
    g_oom_hit = false;

    // Release any fake-fd buffers left behind by a previous compile that
    // errored out partway through (e.g. failed after open() but before
    // harvest_elf() ran). Without this, a broken source file recompiled
    // repeatedly leaks heap on every attempt and never gets it back.
    kfd_reset_all();

    if (!src_name || !src_name[0]) {
        console_print("cc: no source file\n");
        return;
    }

    // Derive output name
    char out_name[64];
    if (out_name_arg && out_name_arg[0]) {
        unsigned long i=0;
        while(out_name_arg[i]&&i<63){out_name[i]=out_name_arg[i];i++;}
        out_name[i]='\0';
    } else {
        // basename, strip extension
        const char* base=src_name;
        for(const char* p=src_name;*p;p++)
            if(*p=='/'||*p=='\\') base=p+1;
        unsigned long i=0;
        while(base[i]&&i<63){out_name[i]=base[i];i++;}
        out_name[i]='\0';
        for(int j=(int)i-1;j>=0;j--)
            if(out_name[j]=='.'){out_name[j]='\0';break;}
    }

    console_print("cc: "); console_print(src_name);
    console_print(" -> "); console_print(out_name);
    console_print("\n");

    // Read source from FAT32
    char* full = fat32_read_file_as_string(src_name);
    if (!full) {
        console_print("cc: cannot read "); console_print(src_name); console_print("\n");
        return;
    }

    // Hook TCC allocator to the kernel heap
    tcc_set_realloc(tcc_kern_realloc);

    // ── Single stage: compile C source → EXE ELF directly ────────────────────
    // Compiling and linking in one TCCState avoids the '' defined twice errors
    // that occur when tcc_add_file merges an externally-produced .o, because
    // TCC's internal linker manages its own anonymous section symbols from
    // scratch without any merge step.
    TCCState* s1 = tcc_new();
    if (!s1) {
        free(full);
        if (g_oom_hit) console_print("cc: out of memory\n");
        else           console_print("cc: tcc_new failed\n");
        return;
    }

    tcc_set_error_func(s1, nullptr, tcc_err_cb);

    // CRITICAL: set -nostdlib/-nostdinc BEFORE tcc_set_output_type.
    // tcc_set_output_type checks s->nostdlib to decide whether to call
    // tccelf_add_crtbegin(). If options are set after, crtbegin is loaded
    // from CONFIG_TCC_CRTPREFIX (a path that doesn't exist here), its
    // symbols get merged in, and every global symbol appears twice.
    tcc_set_options(s1, "-nostdlib -nostdinc");
    tcc_set_lib_path(s1, "/nonexistent");
    tcc_set_output_type(s1, TCC_OUTPUT_EXE);   // nostdlib is now set — safe
    tcc_set_options(s1, "-Wl,-e=_start");
    tcc_set_options(s1, "-Wl,-Ttext=0x08002000");

    int rc = tcc_compile_string(s1, full);
    free(full);

    if (rc < 0) {
        if (g_oom_hit) {
            console_print("cc: out of memory during compilation\n");
        } else {
            console_print("cc: compile error:\n");
            if (g_errlen>0) console_print(g_errbuf);
        }
        tcc_delete(s1); return;
    }

    // Write EXE ELF to RAM buffer via fake fd
    rc = tcc_output_file(s1, "/@tcc/out.elf");
    tcc_delete(s1);

    if (rc < 0) {
        if (g_oom_hit) {
            console_print("cc: out of memory during linking\n");
        } else {
            console_print("cc: link error:\n");
            if (g_errlen>0) console_print(g_errbuf);
        }
        return;
    }

    // Harvest ELF bytes
    unsigned long elf_size=0;
    unsigned char* elf=harvest_elf(&elf_size);

    if (!elf || elf_size<4 ||
        elf[0]!=0x7F||elf[1]!='E'||elf[2]!='L'||elf[3]!='F') {
        if (g_oom_hit) {
            console_print("cc: out of memory while writing output\n");
        } else {
            console_print("cc: bad ELF output (possibly exceeded size cap)\n");
        }
        if (elf) free(elf);
        return;
    }

    char szbuf[64];
    snprintf(szbuf,sizeof(szbuf),"cc: ELF %lu bytes\n",elf_size);
    console_print(szbuf);

    // Write to FAT32
    int wr=fat32_write_file(out_name,elf,(unsigned int)elf_size);
    free(elf);

    if (wr<0) {
        console_print("cc: write to disk failed\n"); return;
    }

    console_print("cc: written '"); console_print(out_name); console_print("'\n");


}
