#include "bochs-2.0/bochs.h"
#include "bochs-2.0/cpu/cpu.h"
#include <cstring>
#include <cstdlib>
extern "C" void *malloc(unsigned int);
extern "C" void free(void *);
// Global objects
BX_CPU_C bx_cpu;
BX_MEM_C bx_mem;
bx_pc_system_c bx_pc_system;
bx_devices_c bx_devices;
bx_simulator_interface_c *SIM = 0;
#if BX_UI_TEXT
void bx_param_num_c::text_print(FILE *fp) { (void)fp; }
int bx_param_num_c::text_ask(FILE *fpin, FILE *fpout) { (void)fpin; (void)fpout; return -1; }

void bx_param_bool_c::text_print(FILE *fp) { (void)fp; }
int bx_param_bool_c::text_ask(FILE *fpin, FILE *fpout) { (void)fpin; (void)fpout; return -1; }

void bx_param_string_c::text_print(FILE *fp) { (void)fp; }
int bx_param_string_c::text_ask(FILE *fpin, FILE *fpout) { (void)fpin; (void)fpout; return -1; }
#endif
// logfunctions
int logfunctions::default_onoff[N_LOGLEV] = {0};
void bx_cpu_c::fpu_init() {}

void bx_cpu_c::FWAIT(bxInstruction_c *) {}
void bx_cpu_c::ESC0(bxInstruction_c *) {}
void bx_cpu_c::ESC1(bxInstruction_c *) {}
void bx_cpu_c::ESC2(bxInstruction_c *) {}
void bx_cpu_c::ESC3(bxInstruction_c *) {}
void bx_cpu_c::ESC4(bxInstruction_c *) {}
void bx_cpu_c::ESC5(bxInstruction_c *) {}
void bx_cpu_c::ESC6(bxInstruction_c *) {}
void bx_cpu_c::ESC7(bxInstruction_c *) {}
logfunctions::logfunctions(void) {
    prefix = 0;
    type = 0;
    logio = 0;
    for (int i = 0; i < N_LOGLEV; ++i) onoff[i] = 0;
}

logfunctions::logfunctions(iofunctions *) {
    prefix = 0;
    type = 0;
    logio = 0;
    for (int i = 0; i < N_LOGLEV; ++i) onoff[i] = 0;
}

logfunctions::~logfunctions(void) {}
void logfunctions::put(char *s) { (void)s; }
void logfunctions::settype(int t) { type = t; }
void logfunctions::ldebug(const char *fmt, ...) { (void)fmt; }
void logfunctions::info(const char *fmt, ...) { (void)fmt; }
void logfunctions::error(const char *fmt, ...) { (void)fmt; }
void logfunctions::panic(const char *fmt, ...) { (void)fmt; }

// bx_object_c
bx_object_c::bx_object_c(bx_id _id) : id(_id), type(0) {}
const char *bx_param_c::default_text_format = "%s";
Bit32u bx_param_num_c::default_base = 10;

// bx_param_c
bx_param_c::bx_param_c(bx_id _id, char *n, char *d)
: bx_object_c(_id)
{
    name = n;
    description = d;
    text_format = default_text_format;
    ask_format = 0;
    runtime_param = 0;
    enabled = 1;
}

const char* bx_param_c::set_default_format(const char *f) {
    const char *old = default_text_format;
    default_text_format = f;
    return old;
}

// bx_param_num_c
bx_param_num_c::bx_param_num_c(
    bx_id _id, char *n, char *d, Bit64s minv, Bit64s maxv, Bit64s initv)
: bx_param_c(_id, n, d)
{
    dependent_list = 0;
    min = minv;
    max = maxv;
    initial_val = initv;
    val.number = initv;
    handler = 0;
    base = default_base;
}

void bx_param_num_c::reset() { val.number = initial_val; }
void bx_param_num_c::set_handler(param_event_handler h) { handler = h; }
void bx_param_num_c::set_dependent_list(bx_list_c *l) { dependent_list = l; }
void bx_param_num_c::set_enabled(int e) { enabled = e; }
Bit64s bx_param_num_c::get64() { return val.number; }
void bx_param_num_c::set(Bit64s v) {
    if (v < min) v = min;
    if (v > max) v = max;
    val.number = handler ? handler(this, 1, v) : v;
}
void bx_param_num_c::set_initial_val(Bit64s v) { initial_val = v; }
void bx_param_num_c::set_range(Bit64u lo, Bit64u hi) {
    min = (Bit64s)lo;
    max = (Bit64s)hi;
}
Bit32u bx_param_num_c::set_default_base(Bit32u v) {
    Bit32u old = default_base;
    default_base = v;
    return old;
}

// bx_param_bool_c
bx_param_bool_c::bx_param_bool_c(bx_id _id, char *n, char *d, Bit64s initv)
: bx_param_num_c(_id, n, d, 0, 1, initv) {}

// bx_param_string_c
bx_param_string_c::bx_param_string_c(
    bx_id _id, char *n, char *d, char *initv, int maxsz)
: bx_param_c(_id, n, d)
{
    if (!initv) initv = (char*)"";
    int need = (int)std::strlen(initv) + 1;
    if (maxsz < 0 || maxsz < need) maxsz = need;

    maxsize = maxsz;
    handler = 0;
    options = 0;
    separator = 0;

    val = (char*)malloc(maxsize);
    initial_val = (char*)malloc(maxsize);

    if (val) {
        std::strncpy(val, initv, maxsize - 1);
        val[maxsize - 1] = 0;
    }
    if (initial_val) {
        std::strncpy(initial_val, initv, maxsize - 1);
        initial_val[maxsize - 1] = 0;
    }
}

bx_param_string_c::~bx_param_string_c() {
    if (val) free(val);
    if (initial_val) free(initial_val);
}

void bx_param_string_c::reset() {
    if (val && initial_val) {
        std::strncpy(val, initial_val, maxsize - 1);
        val[maxsize - 1] = 0;
    }
}

void bx_param_string_c::set_handler(param_string_event_handler h) { handler = h; }

Bit32s bx_param_string_c::get(char *buf, int len) {
    if (!buf || len <= 0 || !val) return 0;
    std::strncpy(buf, val, len - 1);
    buf[len - 1] = 0;
    return (Bit32s)std::strlen(buf);
}

void bx_param_string_c::set(char *buf) {
    if (!buf) buf = (char*)"";
    if (handler) buf = handler(this, 1, buf, maxsize);
    if (val && maxsize > 0) {
        std::strncpy(val, buf, maxsize - 1);
        val[maxsize - 1] = 0;
    }
}

bx_bool bx_param_string_c::equals(const char *buf) {
    if (!val || !buf) return 0;
    return std::strcmp(val, buf) == 0;
}

// simulator interface
bx_simulator_interface_c::bx_simulator_interface_c() {}

// devices
void bx_devices_c::reset(unsigned type) { (void)type; }