#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"

extern "C" void bochs_cpu_init() {
  bx_cpu.initialize();
  bx_cpu.reset(BX_RESET_HARDWARE);
}

extern "C" int bochs_cpu_tick(int n) {
  for (int i = 0; i < n; ++i) {
    BX_CPU_C::cpu_loop();
  }
  return 0;
}

extern "C" unsigned int bochs_cpu_geteip() {
  return bx_cpu.get_instruction_pointer();
}
