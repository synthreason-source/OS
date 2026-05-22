// =====================================================================
// commands_patch.cpp — Snippets to splice into kernel.cpp
// =====================================================================
//
// These are NOT a standalone file. Copy each block into the indicated
// location inside kernel.cpp's handle_command() method, then add the
// helpers near the top of the same translation unit.
//
// All four new commands match the prototype's terminal behavior:
//   matrix  — array store + GEMM (matrix.md)
//   recurse — spawn N Bochs windows running /bin/hello (the screenshot)
//   hello   — shortcut: bochs /bin/hello
//   about   — print build banner
//
// Depends on:
//   • matrix_array.h next to kernel.cpp
//   • TerminalWindow with console_print(const char*)
//   • wm.add_window(...) for spawning windows
//   • get_arg(args, n) and simple_atoi from kernel.cpp
//
// ─────────────────────────────────────────────────────────────────────
// (A) Include + tiny printer adapter — add near the other helpers,
//     just above class TerminalWindow definition (~line 5500).
// ─────────────────────────────────────────────────────────────────────

#include "matrix_array.h"

// NpaPrint adapter: forwards into a TerminalWindow*.
static void npa_term_print(void* ctx, const char* s) {
    static_cast<TerminalWindow*>(ctx)->console_print(s);
}

// Convenience: parse perms string "rwxt" / "rw" / "r--x" → bitmask.
static uint16_t parse_perms(const char* s) {
    if (!s || !*s) return NPA_R | NPA_W | NPA_RX;
    uint16_t p = 0;
    for (; *s; ++s) {
        switch (*s) {
            case 'r': case 'R': p |= NPA_R;  break;
            case 'w': case 'W': p |= NPA_W;  break;
            case 'x': case 'X': p |= NPA_RX; break;
            case 't': case 'T': p |= NPA_TX; break;
            default: break;
        }
    }
    return p;
}
