/*
 * OPTIMIZED KERNEL WITH GRAPHICS STATE MANAGEMENT
 * ================================================
 * All graphics rendering uses atomic frame composition
 * Unified color palette prevents inconsistencies
 * State machine ensures complete frames with no trailing
 *
 * This file used to contain the entire kernel (~10,500 lines) in one
 * translation unit. It has been split into per-component files under
 * kernel_parts/, included below in their original order. This is a pure
 * physical reorganization -- no code was reordered, added, or removed,
 * so the compiled kernel is unchanged. The split points were chosen at
 * brace-depth-0 boundaries (verified with a script) so no class,
 * struct, or function is torn across two files.
 *
 * Order is load-bearing: this is still effectively one translation
 * unit stitched together via #include, not independent compilation
 * units, because later parts rely on types/functions/globals defined
 * earlier (e.g. WindowManager's out-of-class method bodies in
 * 10_window_manager_impl.h need the complete TerminalWindow type from
 * 09_terminal_window.h). Do not reorder these includes.
 */

#include "kernel_parts/00_core_types_and_stdlib.h"
#include "kernel_parts/01_fs_encryption.h"
#include "kernel_parts/02_boot_info_and_graphics_driver.h"
#include "kernel_parts/03_input_ps2_mouse.h"
#include "kernel_parts/04_window_system.h"
#include "kernel_parts/05_io_wait_ps2_funcs.h"
#include "kernel_parts/06_fat32_filesystem_and_explorer.h"
#include "kernel_parts/07_chkdsk_and_hardware.h"
#include "kernel_parts/08_tinyvm_compiler_vm.h"
#include "kernel_parts/09_terminal_window.h"
#include "kernel_parts/10_window_manager_impl.h"
#include "kernel_parts/11_kernel_main.h"
