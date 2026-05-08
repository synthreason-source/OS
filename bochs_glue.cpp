#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"

extern "C" void* __dso_handle = nullptr;
extern "C" int __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void __cxa_finalize(void*) {}

#define MAX_BOCHS_SLOTS 4

struct SlotState {
    Bit8u* mem_base = nullptr;
    Bit32u mem_size = 0;
    Bit32u vaddr_base = 0;
    Bit32u brk_ptr = 0;
    int slot_id = -1;
    bool wants_input = false;
    int (*read_cb)(int) = nullptr;
    void (*write_cb)(int, char) = nullptr;
    void (*exit_cb)(int, int) = nullptr;
};

static SlotState g_slots[MAX_BOCHS_SLOTS];
static int g_active_slot = -1;
static bool g_cpu_ready = false;

static void setup_flat_segment(bx_segment_reg_t& seg, Bit16u sel, bool code) {
    seg.selector.value = sel;
    seg.selector.rpl = 0;
    seg.selector.ti = 0;
    seg.selector.index = sel >> 3;

    bx_descriptor_t& d = seg.cache;
    d.valid = 1;
    d.p = 1;
    d.dpl = 0;
    d.segment = 1;
    d.type = code ? 0x0B : 0x03;
    d.u.segment.base = 0x00000000u;
    d.u.segment.limit_scaled = 0xFFFFFFFFu;
    d.u.segment.g = 1;
    d.u.segment.d_b = 1;
    d.u.segment.avl = 0;
}

static void bochs_cpu_enter_protected_mode() {
    BX_CPU_C* cpu = BX_CPU(0);
    cpu->cr0.val32 |= 0x00000001u;

    setup_flat_segment(cpu->sregs[BX_SEG_REG_CS], 0x08, true);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_SS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_DS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_ES], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_FS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_GS], 0x10, false);

    cpu->invalidate_prefetch_q();
}

static bool mem_read_handler(bx_phy_address addr, unsigned len, void* data, void*) {
    if (g_active_slot < 0) {
        __builtin_memset(data, 0, len);
        return true;
    }

    SlotState& s = g_slots[g_active_slot];
    Bit32u off = (Bit32u)addr;

    if (s.mem_base && off >= s.vaddr_base) {
        off -= s.vaddr_base;
        if (off + len <= s.mem_size) {
            __builtin_memcpy(data, s.mem_base + off, len);
            return true;
        }
    }

    __builtin_memset(data, 0, len);
    return true;
}

static bool mem_write_handler(bx_phy_address addr, unsigned len, void* data, void*) {
    if (g_active_slot < 0) return true;

    SlotState& s = g_slots[g_active_slot];
    Bit32u off = (Bit32u)addr;

    if (s.mem_base && off >= s.vaddr_base) {
        off -= s.vaddr_base;
        if (off + len <= s.mem_size) {
            __builtin_memcpy(s.mem_base + off, data, len);
        }
    }

    return true;
}

static void inject_idt_into_slab(SlotState& s) {
    if (!s.mem_base || s.mem_size < 0x1000) return;

    static const Bit8u stub[12] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xBB, 0x00, 0x00, 0x00, 0x00,
        0xCD, 0x80
    };

    __builtin_memcpy(s.mem_base + 0x000, stub, sizeof(stub));
    s.mem_base[sizeof(stub)] = 0xF4;

    Bit32u handler_va = s.vaddr_base + 0x000;
    Bit8u* idt_base = s.mem_base + 0x100;
    Bit32u idt_va = s.vaddr_base + 0x100;

    Bit8u gate[8];
    gate[0] = (Bit8u)(handler_va & 0xFF);
    gate[1] = (Bit8u)((handler_va >> 8) & 0xFF);
    gate[2] = 0x08;
    gate[3] = 0x00;
    gate[4] = 0x00;
    gate[5] = 0x8E;
    gate[6] = (Bit8u)((handler_va >> 16) & 0xFF);
    gate[7] = (Bit8u)((handler_va >> 24) & 0xFF);

    for (int i = 0; i < 256; i++) {
        __builtin_memcpy(idt_base + i * 8, gate, 8);
    }

    BX_CPU(0)->idtr.base = idt_va;
    BX_CPU(0)->idtr.limit = 256 * 8 - 1;
}

extern "C" void bochs_register_io_callbacks(
    int slot,
    int (*read_cb)(int),
    void (*write_cb)(int, char),
    void (*exit_cb)(int, int))
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].slot_id = slot;
    g_slots[slot].read_cb = read_cb;
    g_slots[slot].write_cb = write_cb;
    g_slots[slot].exit_cb = exit_cb;
}

extern "C" void bochs_set_process_memory(Bit8u* base, Bit32u size, Bit32u vaddr_base) {
    if (g_active_slot < 0) return;

    SlotState& s = g_slots[g_active_slot];

    if (s.mem_base && s.mem_size) {
        BX_MEM(0)->unregisterMemoryHandlers(nullptr,
            (bx_phy_address)s.vaddr_base,
            (bx_phy_address)(s.vaddr_base + s.mem_size - 1));
    }

    s.mem_base = base;
    s.mem_size = size;
    s.vaddr_base = vaddr_base;

    if (base && size) {
        BX_MEM(0)->registerMemoryHandlers(
            nullptr,
            mem_read_handler, mem_write_handler,
            (bx_phy_address)vaddr_base,
            (bx_phy_address)(vaddr_base + size - 1));

        inject_idt_into_slab(s);
    }
}

extern "C" void bochs_finalize_process_memory() {
}

extern "C" void bochs_set_brk(int slot, Bit32u brk_addr) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].brk_ptr = brk_addr;
}

extern "C" void bochs_activate_slot(int slot) {
    g_active_slot = slot;
}

extern "C" void bochs_cpu_init() {
    BX_CPU(0)->initialize();
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    bochs_cpu_enter_protected_mode();
    g_cpu_ready = false;
}

extern "C" int bochs_cpu_tick(int n) {
    if (!g_cpu_ready || g_active_slot < 0) return 0;
    if (!g_slots[g_active_slot].mem_base) return 0;

    g_slots[g_active_slot].wants_input = false;
    for (int i = 0; i < n; ++i) {
        BX_CPU(0)->cpu_loop();
    }
    return 0;
}

extern "C" bool bochs_process_wants_input(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return false;
    return g_slots[slot].wants_input;
}

extern "C" void bochs_cpu_set_eip(Bit32u eip) {
    BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;
    BX_CPU(0)->prev_rip = eip;
    BX_CPU(0)->invalidate_prefetch_q();
    g_cpu_ready = true;
}

extern "C" void bochs_cpu_set_esp(Bit32u esp_val) {
    BX_CPU(0)->gen_reg[BX_32BIT_REG_ESP].dword.erx = esp_val;
}

extern "C" Bit32u bochs_cpu_get_eip() {
    return BX_CPU(0)->get_eip();
}

extern "C" unsigned int bochs_cpu_geteip() {
    return (unsigned int)BX_CPU(0)->get_eip();
}

extern "C" Bit32u bochs_cpu_get_eax() {
    return BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
}