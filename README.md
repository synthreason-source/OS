# Bochs slot hang fix (v7)

## Status

v6 advanced past the `init_memory` hang. Now QEMU resets — different
failure, further along.

## What v7 fixes

The reset is most likely a NULL-deref in libcpu.a's
`generic_cpuid.cc`:

```cpp
void bx_generic_cpuid_t::get_cpuid_leaf(...) const {
    static const char *brand_string =
        (const char *)SIM->get_param_string(BXPN_BRAND_STRING)->getptr();
    static bool cpuid_limit_winnt =
        SIM->get_param_bool(BXPN_CPUID_LIMIT_WINNT)->get();
    ...
}
```

`get_cpuid_leaf` is called from `BX_CPU(0)->reset(BX_RESET_HARDWARE)`
during CPU init (via the CPUID emulation path). Our KernelSIM had
`get_param_string` returning nullptr, so `nullptr->getptr()` host
-faults and triple-faults QEMU.

v7 makes every `KernelSIM::get_param_*` return a pre-constructed
file-scope dummy object:

```cpp
static bx_param_bool_c   s_dummy_bool  (nullptr, "dummy","dummy","dummy",0,0);
static bx_param_num_c    s_dummy_num   (nullptr, "dummy","dummy","dummy",0,0,0,0);
static bx_param_string_c s_dummy_string(nullptr, "dummy","dummy","dummy","",1);
```

These are constructed during the `__init_array` global-ctor pass at
boot, **before** any guest workload runs. Calls then just return their
addresses with no per-call construction.

The v5b hang was in the lazy first-call construction of a function
-local static `bx_param_bool_c dummy`. By the time `init_memory` ran,
the kernel heap had been hammered by several big allocations
(3.13 MB vector, 4 MB memory_handlers); a heap-state-dependent bug
in the allocator may have been what wedged the ctor's three small
`new char[6]` calls. Doing the construction at boot, before any of
those allocations happen, sidesteps that path.

## Cumulative root causes (v1 through v7)

| # | Description                                                | Fixed in |
|---|------------------------------------------------------------|----------|
| 1 | `bochs_set_process_memory` runs before BX_MEM is initialised | v2     |
| 2a | `BX_MEM_C::init_memory()`'s `get_param_bool` hangs           | v6     |
| 2b | libcpu.a `generic_cpuid.cc` calls SIM->get_param_*; nullptr returns triple-fault | v7 |
| 3 | `registerMemoryHandlers` registered with `da_handler = NULL`   | v4     |
| 4 | IDT trap stub recurses on `int $0x80`                          | v1     |

## What to look for on the next run

The top-row breadcrumbs should now advance through:

```
1234 AMBHIpPfF$5SM…
```

then `bochs_glue.cpp`'s breadcrumbs at columns 70/72/73 should start
firing as `bochs_cpu_tick` runs. Hello's `HELLO\n` should appear in
the terminal, then `[diag] elf_io_exit slot=0 code=0`, and the
shell prompt should return.

### Possible failure modes

If the boot screen never appears (no init messages, blank screen):
the file-scope dummy ctors hung at boot. The bug is in the
`bx_param_*_c` ctor chain itself, not in the lazy-init path. In
that case we'd need to fall back to either:
- skipping every `SIM->get_param_*` call site (intrusive — many
  call sites in libcpu.a)
- returning a manually-constructed fake object with a hand-written
  vtable

If boot completes but `hello` still resets QEMU, the next failure
is further along. Capture the top-row breadcrumbs at the moment of
reset; the suffix tells us which step failed.

## Files changed

* **`bochs_glue.cpp`** — Bugs 1, 3, 4.
* **`bochs_infra.cpp`** — All `KernelSIM::get_param_*` return file
  -scope dummies (v7). Custom `init_memory` with per-step
  breadcrumbs, hard-coded `pci_enabled = false` (v6). No-op
  `register_state`. Port 0xE8 routing (Bug 4).
* **`kernel.cpp`** — `proc.active` recheck after Bochs tick (Bug 4).
* **`bochs_stub.cpp`** — `bochs_guest_exit` no-op for BOCHS=0.

Untouched: `bochs_cstubs.c`, `boot.S`, `setjmp.S`, `Makefile`,
`linker.ld`, `fixes.h`, `font.h`, `instrument_stub.h`,
`busybox_stub.c`, `hello.c`.

## Verification

`bochs_glue.cpp` and `bochs_infra.cpp` syntax-check cleanly with
`g++ -m32` against a freshly configured `bochs-2.7` tree.
