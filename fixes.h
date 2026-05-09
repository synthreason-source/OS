#pragma once
// fixes.h - freestanding stack protector shims
// Use __attribute__((weak)) so this can be included in multiple TUs
// without multiple-definition linker errors.

extern "C" {
  // Null guard = no checks performed
  __attribute__((weak)) unsigned int __stack_chk_guard[8] = {0};
  
  // Halt on fail (never reached with null guard)
  __attribute__((weak)) void __stack_chk_fail(void) {
    asm volatile("cli; hlt");
    __builtin_unreachable();
  }
}
