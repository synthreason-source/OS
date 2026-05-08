#pragma once
// fixes.h - freestanding stack protector shims

extern "C" {
  // Null guard = no checks performed
  unsigned int __stack_chk_guard[8] = {0};
  
  // Halt on fail (never reached with null guard)
  void __stack_chk_fail(void) {
    asm volatile("cli; hlt");
    __builtin_unreachable();
  }
}