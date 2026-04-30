/* bochs_cstubs.c — freestanding C stdlib for bochs + libgcc_eh */
/* NO system headers. Compiled with -ffreestanding. */

typedef unsigned long  size_t;
typedef long           ssize_t;
typedef long           time_t;
typedef long long      off64_t;
typedef int            pthread_mutex_t;

/* ── Internal bump allocator for bochs exception frame tables ─────────────── */
/* libgcc_eh calls malloc/free to register unwinding info. We give it a small   */
/* static pool since we never actually unwind (exception paths just halt).       */
static char  _bheap[128 * 1024];
static int   _bptr = 0;

void* malloc(size_t n) {
    n = (n + 7) & ~7u;  /* align to 8 bytes */
    if (_bptr + (int)n > (int)sizeof(_bheap)) { __asm__("cli;hlt"); }
    void* p = _bheap + _bptr;
    _bptr += n;
    return p;
}
void free(void* p)   { (void)p; }   /* bump allocator: no-op free */
void abort(void)     { __asm__("cli; hlt"); __builtin_unreachable(); }

/* ── String functions ─────────────────────────────────────────────────────── */
size_t strlen(const char* s)  { size_t n=0; while(s[n]) n++; return n; }
int strcmp(const char* a, const char* b) {
    while(*a && *a==*b){a++;b++;} return (unsigned char)*a-(unsigned char)*b; }
int strncmp(const char* a, const char* b, size_t n) {
    while(n&&*a&&*a==*b){a++;b++;n--;} return n?(unsigned char)*a-(unsigned char)*b:0; }
char* strncpy(char* d, const char* s, size_t n) {
    size_t i=0; for(;i<n&&s[i];i++)d[i]=s[i]; for(;i<n;i++)d[i]=0; return d; }
char* strcat(char* d, const char* s) { char* r=d; while(*d)d++; while((*d++=*s++)); return r; }
char* strncat(char* d, const char* s, size_t n) {
    char* r=d; while(*d)d++; while(n--&&*s)*d++=*s++; *d=0; return r; }
const char* strstr(const char* h, const char* n) {
    if(!*n)return h; for(;*h;h++){const char*a=h,*b=n;while(*a&&*b&&*a==*b){a++;b++;}if(!*b)return h;} return 0; }
int strcasecmp(const char* a, const char* b) {
    while(*a&&(*a|32)==(*b|32)){a++;b++;} return (*a|32)-(*b|32); }
void* memcpy(void* d,const void* s,size_t n){char*dd=(char*)d;const char*ss=(const char*)s;while(n--)*dd++=*ss++;return d;}
void* memset(void* d,int c,size_t n){char*p=(char*)d;while(n--)*p++=(char)c;return d;}
void* memmove(void* d,const void* s,size_t n){char*dd=(char*)d;const char*ss=(const char*)s;if(dd<ss){while(n--)*dd++=*ss++;}else{dd+=n;ss+=n;while(n--)*--dd=*--ss;}return d;}
int   memcmp(const void* a,const void* b,size_t n){const unsigned char*p=(const unsigned char*)a,*q=(const unsigned char*)b;while(n--){if(*p!=*q)return *p-*q;p++;q++;}return 0;}

/* ── Fortified wrappers ───────────────────────────────────────────────────── */
char* __strcpy_chk(char* d,const char* s,size_t dsz){(void)dsz;char*r=d;while((*d++=*s++));return r;}
char* __strncpy_chk(char* d,const char* s,size_t n,size_t dsz){(void)dsz;return strncpy(d,s,n);}
void* __memcpy_chk(void* d,const void* s,size_t n,size_t dsz){(void)dsz;return memcpy(d,s,n);}
void* __memset_chk(void* d,int c,size_t n,size_t dsz){(void)dsz;return memset(d,c,n);}
int __sprintf_chk(char* b,int f,size_t dsz,const char* fmt,...){(void)f;(void)dsz;(void)fmt;if(b)*b=0;return 0;}
int __snprintf_chk(char* b,size_t n,int f,size_t dsz,const char* fmt,...){(void)f;(void)dsz;(void)fmt;if(b&&n)b[0]=0;return 0;}
int __vsprintf_chk(char* b,int f,size_t dsz,const char* fmt,void* ap){(void)f;(void)dsz;(void)fmt;(void)ap;if(b)*b=0;return 0;}
int __fprintf_chk(void* fp,int f,const char* fmt,...){(void)fp;(void)f;(void)fmt;return 0;}
int __printf_chk(int f,const char* fmt,...){(void)f;(void)fmt;return 0;}
void __stack_chk_fail(void){abort();}
void __assert_fail(const char* a,const char* b,unsigned c,const char* d){(void)a;(void)b;(void)c;(void)d;abort();}

/* ── Math / random / time ─────────────────────────────────────────────────── */
double pow(double a,double b){(void)a;(void)b;return 0.0;}
time_t time(time_t* t){if(t)*t=0;return 0;}
void srand(unsigned s){(void)s;}
int  rand(void){return 42;}

/* ── pthreads (libgcc_eh mutex) ───────────────────────────────────────────── */
int pthread_mutex_lock(pthread_mutex_t* m)  {(void)m;return 0;}
int pthread_mutex_unlock(pthread_mutex_t* m){(void)m;return 0;}

/* ── Dynamic linker ───────────────────────────────────────────────────────── */
int _dl_find_object(void* addr,void* result){(void)addr;(void)result;return -1;}

/* ── sscanf / strto* ──────────────────────────────────────────────────────── */
int __isoc23_sscanf(const char* s,const char* f,...){(void)s;(void)f;return 0;}
unsigned long long __isoc23_strtoull(const char* s,char** e,int b){(void)s;(void)e;(void)b;return 0;}
long __isoc23_strtol(const char* s,char** e,int b){(void)s;(void)e;(void)b;return 0;}
double strtod(const char* s,char** e){(void)s;(void)e;return 0.0;}
int snprintf(char* b,size_t n,const char* f,...){(void)n;(void)f;if(b&&n)*b=0;return 0;}

/* ── FILE stubs ───────────────────────────────────────────────────────────── */
typedef struct{int fd;}FILE;
static FILE _null_file={-1};
FILE* fopen64(const char* p,const char* m){(void)p;(void)m;return 0;}
FILE* tmpfile64(void){return 0;}
int   fclose(FILE* f){(void)f;return 0;}
int   feof(FILE* f){(void)f;return 1;}
char* fgets(char* s,int n,FILE* f){(void)s;(void)n;(void)f;return 0;}
int   fflush(FILE* f){(void)f;return 0;}
size_t fread(void* p,size_t sz,size_t n,FILE* f){(void)p;(void)sz;(void)n;(void)f;return 0;}
size_t fwrite(const void* p,size_t sz,size_t n,FILE* f){(void)p;(void)sz;(void)n;(void)f;return 0;}
int   fseeko64(FILE* f,off64_t o,int w){(void)f;(void)o;(void)w;return -1;}
FILE* stdout = &_null_file;
FILE* stderr = &_null_file;
int fprintf(FILE* f, const char* fmt, ...){(void)f;(void)fmt;return 0;}
int fputs(const char* s, FILE* f){(void)s;(void)f;return 0;}

/* ── POSIX ────────────────────────────────────────────────────────────────── */
int open64(const char* p,int f,...){(void)p;(void)f;return -1;}
int fstat64(int fd,void* st){(void)fd;(void)st;return -1;}
ssize_t read(int fd,void* buf,size_t n){(void)fd;(void)buf;(void)n;return -1;}
int close(int fd){(void)fd;return 0;}

/* ── bochs-specific globals ───────────────────────────────────────────────── */
int simulate_xapic = 0;

/* _setjmp and __longjmp_chk: bochs cpu_loop uses these for exception handling.
   We provide real implementations so bochs can use them at runtime. */

/* jmp_buf layout for i386: eip, esp, ebp, ebx, esi, edi + padding */
typedef unsigned int jmp_buf_i386[8];

int _setjmp(jmp_buf_i386 env) {
    unsigned int eip_ret, esp_ret;
    __asm__ volatile(
        "movl %%esp, %0\n"
        "movl $0, %%eax\n"
        : "=m"(env[1]), "=a"(eip_ret)
        :
        : "memory"
    );
    /* Store caller's return address as the saved EIP */
    env[0] = (unsigned int)__builtin_return_address(0);
    env[2] = (unsigned int)__builtin_frame_address(0);
    return 0;
}

/* longjmp halts — in bochs this is only called on fatal CPU exceptions
   (double fault, triple fault) which should terminate the process anyway. */
void __longjmp_chk(jmp_buf_i386 env, int val) {
    (void)env; (void)val;
    /* The calling process should be killed; halt the bochs CPU path */
    __asm__ volatile("cli; hlt");
    __builtin_unreachable();
}

/* pthread_mutex_destroy - called by iofunctions dtor (which we never trigger) */
int pthread_mutex_destroy(int* m) { (void)m; return 0; }
int pthread_mutex_init(int* m, const void* attr) { (void)m; (void)attr; return 0; }
