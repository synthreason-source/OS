/* ====================================================================
 * tcc_glue.h — freestanding TCC compiler integration for the kernel.
 *
 * Architecture mirrors the Bochs integration exactly:
 *
 *   tcc_glue.cpp   — real implementation, compiled with TCC=1.
 *                    libtcc.so is embedded into the kernel ELF at
 *                    build time (via objcopy, same as busybox/hello)
 *                    as linker symbols libtcc_start / libtcc_end.
 *                    tcc_module_init() loads directly from those
 *                    symbols — no FAT32 read needed at init time.
 *
 *   tcc_stub.cpp   — no-op fallback, compiled with TCC=0. Every
 *                    function returns a clear error code.
 *
 * Build-time flow (mirrors busybox):
 *   1. Makefile.tcc downloads tcc-0.9.27.tar.bz2 from savannah.gnu.org
 *   2. Builds libtcc.so (i386, stripped, self-contained)
 *   3. objcopy --add-section embeds it → libtcc_embed.o
 *      with symbols: libtcc_start, libtcc_end
 *   4. Kernel links libtcc_embed.o + tcc_glue.o
 *   5. At boot, kernel calls extract_libtcc_to_filesystem() which
 *      writes libtcc.so to FAT32 (same as extract_busybox_to_filesystem)
 *      so the `tcc` command can also write compiled ELFs there.
 *
 * Kernel shell usage:
 *   tcc <source.c>           — compile source.c → source (ELF i386)
 *   tcc <source.c> -o <out>  — compile with explicit output name
 * ==================================================================== */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── One-shot initialisation ─────────────────────────────────────────────
 * Call once during kernel startup, after FAT32 is mounted —
 * exactly like extract_busybox_to_filesystem() and
 * extract_hello_to_filesystem() in kernel.cpp.
 *
 * Skips the write if "libtcc.so" already exists on FAT32 with the
 * correct size (idempotent across reboots).
 *
 * Returns true on success or if the file was already current. */
bool extract_libtcc_to_filesystem(void);

/* ── One-shot initialisation ─────────────────────────────────────────────
 * Called once during kernel startup (or lazily on first `tcc` command).
 * Loads libtcc directly from the embedded linker symbols (no FAT32 read).
 * In tcc_stub.cpp this is a no-op.
 * Returns 0 on success, negative on failure. */
int  tcc_module_init(void);

/* ── Compiler entry point ────────────────────────────────────────────────
 * Compile the C source file `src_filename` (read from FAT32) and write
 * the resulting i386 ELF to `out_filename` (written to FAT32).
 *
 * Parameters
 *   src_filename  — FAT32 filename of the C source (e.g. "hello.c")
 *   out_filename  — FAT32 filename for the ELF output (e.g. "hello")
 *                   May be NULL; the glue then derives it by stripping
 *                   the extension from src_filename.
 *   extra_flags   — NULL-terminated list of extra -D/-I/-W flags,
 *                   or NULL for none.
 *
 * Returns 0 on success, negative errno-style on failure:
 *   TCC_ERR_NOT_INIT   (-1)  — tcc_module_init() not called / failed
 *   TCC_ERR_NO_SRC     (-2)  — source file not found on FAT32
 *   TCC_ERR_COMPILE    (-3)  — TCC reported a compilation error
 *   TCC_ERR_OUTPUT     (-4)  — could not write ELF to FAT32
 *   TCC_ERR_NOMEM      (-5)  — kernel allocator OOM
 */
int  tcc_compile_file(const char* src_filename,
                      const char* out_filename,
                      const char* const* extra_flags);

#define TCC_ERR_NOT_INIT  (-1)
#define TCC_ERR_NO_SRC    (-2)
#define TCC_ERR_COMPILE   (-3)
#define TCC_ERR_OUTPUT    (-4)
#define TCC_ERR_NOMEM     (-5)

/* ── Status / diagnostics ────────────────────────────────────────────────*/
int         tcc_module_available(void);
const char* tcc_last_error(void);

#ifdef __cplusplus
}
#endif
