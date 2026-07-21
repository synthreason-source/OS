#pragma once
// 09_terminal_window.h
// TerminalWindow: the in-OS terminal/shell, including its nested
// AES-128 crypto and disk-password subsystems and the ELF loader used
// by the 'bochs' command.
// Extracted from kernel.cpp (original lines 6669-8921) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.


// =============================================================================
// TERMINAL WINDOW IMPLEMENTATION
// =============================================================================
static constexpr int TERM_HEIGHT = 35;
static constexpr int TERM_WIDTH  = 120;
char prompt_buffer[TERM_WIDTH];

// =============================================================================
// MATRIX ARRAY STORE + DESKTOP SUITE  (patch — see OS-main-patch/INTEGRATION.md)
// =============================================================================
#include "../matrix_array.h"
#include "../desktop_suite/launcher.h"

// parse "rwxt" → bitmask of NPA_R/W/RX/TX. Default: r+w+x if empty.
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

// NpaPrint adapter — body defined after TerminalWindow is complete.
void npa_term_print(void* ctx, const char* s);

class TerminalWindow : public Window {
private:
    // Terminal state
    char buffer[TERM_HEIGHT][TERM_WIDTH];
    int line_count;
    char current_line[TERM_WIDTH];
    int line_pos;

    // True when the last character pushed by console_print() was a '\n'
    // (or no output has been printed yet). When false, the next
    // console_print() call must CONTINUE the current buffer line rather
    // than starting a fresh one. This is what stops chatty guest output
    // — which arrives a few bytes at a time, one console_print() per
    // tick batch — from getting a spurious line break every few bytes.
    bool output_at_line_start = true;

    // Editor state
    bool in_editor;
    char edit_filename[128];
    char** edit_lines;
    int edit_line_count;
    int edit_current_line;
    int edit_cursor_col;
    int edit_scroll_offset;

    // Prompt visual state for multi-line input
    int prompt_visual_lines;
    char private_startup_cmd[256];
// Editor viewport settings
static constexpr int EDIT_ROWS = 35;       // rows visible in the editor area
static constexpr int EDIT_COL_PIX = 8;     // font width
static constexpr int EDIT_LINE_PIX = 10;   // line height
// Column width at which the editor wraps a line, both while typing and
// when a file is first loaded into the editor (see the "edit" command
// handler). Keeping this a single shared constant guarantees a loaded
// file wraps identically to how it would look if it had been typed.
static constexpr int EDITOR_WRAP_WIDTH = 75;
public:  // put_char overrides Window::put_char
void put_char(char c) override {
        if (in_editor) return; // Don't mess with editor

        // Ensure we have at least one line
        if (line_count == 0) {
            push_line("");
        }

        // Get the last line in the buffer
        char* line = buffer[line_count - 1];
        int len = strlen(line);

        if (c == '\n') {
            push_line(""); // Real newline
        } 
        else if (c == '\b') {
            if (len > 0) {
                line[len - 1] = 0; // Remove last char
            }
        } 
        else if (c >= 32 && c <= 126) {
            // Check if line is full
            if (len < TERM_WIDTH - 1) {
                line[len] = c;
                line[len + 1] = 0;
            } else {
                // Wrap to new line
                char temp[2] = {c, 0};
                push_line(temp);
            }
        }
    }
void editor_clamp_cursor_to_line() {
    if (edit_current_line < 0) edit_current_line = 0;
    if (edit_current_line >= edit_line_count) edit_current_line = edit_line_count - 1;
    if (edit_current_line < 0) edit_current_line = 0; // handle empty
    if (edit_line_count > 0) {
        int len = (int)strlen(edit_lines[edit_current_line]);
        if (edit_cursor_col > len) edit_cursor_col = len;
        if (edit_cursor_col < 0) edit_cursor_col = 0;
    } else {
        edit_cursor_col = 0;
    }
}

void editor_ensure_cursor_visible() {
    if (edit_current_line < edit_scroll_offset) {
        edit_scroll_offset = edit_current_line;
        if (edit_scroll_offset < 0) edit_scroll_offset = 0;
    } else if (edit_current_line >= edit_scroll_offset + EDIT_ROWS) {
        edit_scroll_offset = edit_current_line - (EDIT_ROWS - 1);
    }
}
private:
    // Insert a new line at a given index, copying the provided text into it.
    void editor_insert_line_at(int index, const char* text) {
        if (index < 0 || index > edit_line_count) return;

        char** new_lines = new char*[edit_line_count + 1];

        for (int i = 0; i < index; ++i) {
            new_lines[i] = edit_lines[i];
        }

        new_lines[index] = new char[TERM_WIDTH];
        memset(new_lines[index], 0, TERM_WIDTH);
        if (text) {
            strncpy(new_lines[index], text, TERM_WIDTH - 1);
        }

        for (int i = index; i < edit_line_count; ++i) {
            new_lines[i + 1] = edit_lines[i];
        }

        if (edit_lines) {
            delete[] edit_lines;
        }
        edit_lines = new_lines;
        edit_line_count++;
    }

    // Delete the line at a given index.
    void editor_delete_line_at(int index) {
        if (index < 0 || index >= edit_line_count || edit_line_count <= 1) return;

        delete[] edit_lines[index];

        char** new_lines = new char*[edit_line_count - 1];
        
        for (int i = 0; i < index; ++i) {
            new_lines[i] = edit_lines[i];
        }

        for (int i = index + 1; i < edit_line_count; ++i) {
            new_lines[i - 1] = edit_lines[i];
        }

        delete[] edit_lines;
        edit_lines = new_lines;
        edit_line_count--;
    }

    // Get visible columns for the first prompt line (accounts for "> ")
    int term_cols_first() const {
        int cols = (w - 10) / 8;
        cols -= 2;
        if (cols < 1) cols = 1;
        if (cols > 118) cols = 118;
        return cols;
    }

    // Get visible columns for continuation lines or general output
    int term_cols_cont() const {
        int cols = (w - 10) / 8;
        if (cols < 1) cols = 1;
        if (cols > 118) cols = 118;
        return cols;
    }

    // Removes the last N lines from the terminal buffer (used to refresh prompt)
    void remove_last_n_lines(int n) {
        while (n-- > 0 && line_count > 0) {
            memset(buffer[line_count - 1], 0, 120);
            line_count--;
        }
    }

    // Finds the best position to wrap a string within max_cols
    int find_wrap_pos(const char* s, int max_cols) {
        int len = (int)strlen(s);
        if (len <= max_cols) return len;

        int wrap_at = max_cols;
        for (int i = max_cols; i > 0; --i) {
            if (s[i] == ' ' || s[i] == '\t' || s[i] == '-') {
                wrap_at = i;
                break;
            }
        }
        return wrap_at;
    }

    // Pushes a single line segment of the prompt to the terminal buffer
    void append_prompt_line(const char* seg, bool first) {
        char linebuf[120];
        linebuf[0] = 0;
        if (first) {
            snprintf(linebuf, 120, "> %s", seg);
        } else {
            snprintf(linebuf, 120, "  %s", seg);
        }
        push_line(linebuf);
    }

    // Redraws the entire multi-line prompt based on `current_line`
    void update_prompt_display() {
        if (prompt_visual_lines > 0) {
            remove_last_n_lines(prompt_visual_lines);
            prompt_visual_lines = 0;
        }

        const char* p = current_line;
        bool first = true;
        int seg_count = 0;

        if (*p == '\0') {
            append_prompt_line("", true);
            prompt_visual_lines = 1;
            return;
        }

        while (*p) {
            int max_cols = first ? term_cols_first() : term_cols_cont();
            int take = find_wrap_pos(p, max_cols);

            char seg[120];
            strncpy(seg, p, take);
            seg[take] = '\0';
            
            int trim = (int)strlen(seg);
            while (trim > 0 && (seg[trim-1] == ' ' || seg[trim-1] == '\t')) {
                seg[--trim] = '\0';
            }

            append_prompt_line(seg, first);
            seg_count++;

            p += take;
            if (*p == ' ' || *p == '\t') p++;
            first = false;
        }
        prompt_visual_lines = seg_count;
    }

    // Append a text fragment to the LAST buffer line (no re-wrapping of
    // existing content, no newline). Used by push_wrapped_text to
    // continue a line that a previous console_print() call left
    // unterminated.
    //
    // `cols` is the window's CURRENT visible column count
    // (term_cols_cont()), not TERM_WIDTH. TERM_WIDTH is just the size of
    // the internal char buffer (120) — it has nothing to do with how
    // many characters actually fit on screen. draw_string() draws
    // glyphs with no clipping against the window border, so a
    // continuation line that's allowed to grow up to TERM_WIDTH-1 chars
    // (as it previously did) draws straight past the right edge of any
    // window narrower than ~119 columns. That was the source of the
    // "glitchy" streaking/overflow seen with chatty ELF guest output:
    // each chunk just kept appending to the same on-screen row instead
    // of wrapping at the column the window can actually display.
    void append_to_last_line(const char* frag, int cols) {
        if (!frag || !*frag) return;
        if (cols < 1) cols = 1;
        if (cols > TERM_WIDTH - 1) cols = TERM_WIDTH - 1;
        if (line_count == 0) push_line("");
        char* line = buffer[line_count - 1];
        int len = (int)strlen(line);
        while (*frag) {
            if (len >= cols) {
                push_line("");
                line = buffer[line_count - 1];
                len  = 0;
            }
            line[len++] = *frag++;
            line[len]   = '\0';
        }
    }

    // Pushes word-wrapped text (from console_print) to the buffer.
    //
    // A single logical output line is only ever terminated by an actual
    // '\n' in the input. Text that arrives WITHOUT a trailing newline
    // leaves the line "open": output_at_line_start is set false, and the
    // next call continues that same buffer line via append_to_last_line.
    // Previously every call unconditionally push_line()'d its text, so a
    // guest streaming output a few bytes per tick (one console_print per
    // batch) got a line break every few bytes.
    void push_wrapped_text(const char* s, int cols) {
        const char* p = s;
        while (*p) {
            const char* nl = strchr(p, '\n');
            bool has_newline = (nl != nullptr);
            if (!nl) nl = p + strlen(p);

            char line[512]; // Temporary buffer for a logical line
            int len = nl - p;
            if (len > 511) len = 511;
            strncpy(line, p, len);
            line[len] = '\0';

            if (len == 0) {
                // Empty segment. If it came from a real '\n' it is a
                // blank line — but only "blank" if the current line was
                // already started fresh; otherwise the '\n' just closes
                // the open line and emits nothing extra.
                if (has_newline && output_at_line_start) {
                    push_line("");
                }
            } else if (!output_at_line_start) {
                // Continue the open buffer line. We intentionally do NOT
                // re-wrap already-drawn content here; append_to_last_line
                // spills onto a fresh line once it hits the window's
                // actual visible width.
                append_to_last_line(line, cols);
            } else {
                // Fresh line: word-wrap as before.
                const char* q = line;
                while (*q) {
                    int take = find_wrap_pos(q, cols);
                    char seg[120];
                    strncpy(seg, q, take);
                    seg[take] = '\0';

                    int trim = (int)strlen(seg);
                    while (trim > 0 && (seg[trim-1] == ' ' || seg[trim-1] == '\t')) {
                        seg[--trim] = '\0';
                    }

                    push_line(seg);
                    q += take;
                    if (*q == ' ' || *q == '\t') q++;
                }
            }

            // The line is "closed" (next text starts fresh) only when we
            // actually consumed a '\n'. Otherwise it stays open so the
            // following console_print() continues it.
            output_at_line_start = has_newline;

            p = (*nl == '\n') ? nl + 1 : nl;
        }
    }

    // --- END OF MODULE ---

    void scroll() {
        memmove(buffer[0], buffer[1], (TERM_HEIGHT - 1) * TERM_WIDTH);
        memset(buffer[TERM_HEIGHT - 1], 0, TERM_WIDTH);
    }

    void push_line(const char* s) {
        if (line_count >= TERM_HEIGHT) {
            scroll();
            strncpy(buffer[TERM_HEIGHT - 1], s, TERM_WIDTH - 1);
        } else {
            strncpy(buffer[line_count], s, TERM_WIDTH - 1);
            line_count++;
        }
    }
    void print_prompt() { 
        snprintf(prompt_buffer, TERM_WIDTH, "%s> %s", current_directory_path, current_line);
        if (line_count > 0) {
            strncpy(buffer[line_count-1], prompt_buffer, TERM_WIDTH - 1);
        } else {
            push_line(prompt_buffer);
        }
    }
	
// =============================================================================
// AES-128 ENCRYPTION - GLOBAL (PLACE BEFORE WINDOW CLASS)
// =============================================================================
// AES S-box (256 entries)
static constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box (256 entries)
static constexpr uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static constexpr uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


class AES128 {
private:
    uint8_t round_keys[176];
    uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
    void key_expansion(const uint8_t* key) {
        memcpy(round_keys, key, 16);
        for (int i = 4; i < 44; i++) {
            uint8_t temp[4];
            memcpy(temp, &round_keys[(i-1)*4], 4);
            if (i % 4 == 0) {
                uint8_t k = temp[0];
                temp[0] = sbox[temp[1]] ^ rcon[i/4];
                temp[1] = sbox[temp[2]];
                temp[2] = sbox[temp[3]];
                temp[3] = sbox[k];
            }
            for (int j = 0; j < 4; j++) round_keys[i*4 + j] = round_keys[(i-4)*4 + j] ^ temp[j];
        }
    }
    void add_round_key(uint8_t* state, int round) {
        for (int i = 0; i < 16; i++) state[i] ^= round_keys[round * 16 + i];
    }
    void sub_bytes(uint8_t* state) { for (int i = 0; i < 16; i++) state[i] = sbox[state[i]]; }
    void inv_sub_bytes(uint8_t* state) { for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]]; }
    void shift_rows(uint8_t* state) {
        uint8_t temp;
        temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
    }
    void inv_shift_rows(uint8_t* state) {
        uint8_t temp;
        temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
    }
    void mix_columns(uint8_t* state) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
            state[i*4]   = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
            state[i*4+1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
            state[i*4+2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
            state[i*4+3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
        }
    }
    void inv_mix_columns(uint8_t* state) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
            state[i*4]   = xtime(xtime(xtime(s0) ^ s0) ^ xtime(xtime(s1))) ^ xtime(xtime(s2) ^ s2) ^ xtime(s3) ^ s3;
            state[i*4+1] = xtime(s0) ^ s0 ^ xtime(xtime(xtime(s1) ^ s1) ^ xtime(xtime(s2))) ^ xtime(xtime(s3) ^ s3);
            state[i*4+2] = xtime(xtime(s0) ^ s0) ^ xtime(s1) ^ s1 ^ xtime(xtime(xtime(s2) ^ s2) ^ xtime(xtime(s3)));
            state[i*4+3] = xtime(xtime(xtime(s0))) ^ xtime(xtime(s1) ^ s1) ^ xtime(s2) ^ s2 ^ xtime(xtime(xtime(s3) ^ s3));
        }
    }
public:
    void set_key(const uint8_t* key) { key_expansion(key); }
    void encrypt_block(uint8_t* block) {
        add_round_key(block, 0);
        for (int round = 1; round < 10; round++) {
            sub_bytes(block); shift_rows(block); mix_columns(block); add_round_key(block, round);
        }
        sub_bytes(block); shift_rows(block); add_round_key(block, 10);
    }
    void decrypt_block(uint8_t* block) {
        add_round_key(block, 10);
        for (int round = 9; round > 0; round--) {
            inv_shift_rows(block); inv_sub_bytes(block); add_round_key(block, round); inv_mix_columns(block);
        }
        inv_shift_rows(block); inv_sub_bytes(block); add_round_key(block, 0);
    }
};

void hex_to_bytes(const char* hex, uint8_t* bytes, int len) {
    for (int i = 0; i < len; i++) {
        uint8_t high = hex[i*2], low = hex[i*2+1];
        if (high >= '0' && high <= '9') high = high - '0';
        else if (high >= 'a' && high <= 'f') high = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F') high = high - 'A' + 10;
        if (low >= '0' && low <= '9') low = low - '0';
        else if (low >= 'a' && low <= 'f') low = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F') low = low - 'A' + 10;
        bytes[i] = (high << 4) | low;
    }
}

void bytes_to_hex(const uint8_t* bytes, char* hex, int len) {
    const char* hex_chars = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex[i*2] = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[i*2+1] = hex_chars[bytes[i] & 0xF];
    }
    hex[len*2] = '\0';
}

void pkcs7_pad(uint8_t* data, size_t len) {
    size_t pad_len = 16 - (len % 16);
    for (size_t i = 0; i < pad_len; ++i) data[len + i] = static_cast<uint8_t>(pad_len);
}

bool pkcs7_unpad(uint8_t* data, size_t& len) {
    if (len == 0) return false;
    size_t pad_len = data[len - 1];
    if (pad_len > 16 || pad_len > len) return false;
    for (size_t i = 1; i <= pad_len; ++i) {
        if (data[len - i] != static_cast<uint8_t>(pad_len)) return false;
    }
    len -= pad_len;
    return true;
}

bool aes_encrypt_file(const char* key_hex, const char* infile, const char* outfile) {
    char* content = fat32_read_file_as_string(infile);
    if (!content) return false;
    size_t len = strlen(content);
    size_t padded_len = ((len + 15) / 16) * 16;
    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, content, len);
    pkcs7_pad(padded, len);
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);
    AES128 aes; aes.set_key(key);
    for (size_t i = 0; i < padded_len / 16; ++i) aes.encrypt_block(padded + i * 16);
    int result = fat32_write_file(outfile, padded, static_cast<uint32_t>(padded_len));
    delete[] padded; delete[] content;
    return result == 0;
}

bool aes_decrypt_file(const char* key_hex, const char* infile, const char* outfile) {
    char* enc_content = fat32_read_file_as_string(infile);
    if (!enc_content) return false;
    size_t enc_len = strlen(enc_content);
    if (enc_len % 16 != 0) { delete[] enc_content; return false; }
    uint8_t* data = reinterpret_cast<uint8_t*>(enc_content);
    uint8_t key[16]; hex_to_bytes(key_hex, key, 16);
    AES128 aes; aes.set_key(key);
    for (size_t i = 0; i < enc_len / 16; ++i) aes.decrypt_block(data + i * 16);
    if (!pkcs7_unpad(data, enc_len)) { delete[] enc_content; return false; }
    int result = fat32_write_file(outfile, data, static_cast<uint32_t>(enc_len));
    delete[] enc_content;
    return result == 0;
}	
static char g_startup_cmd_unused[256];




// Find free process slot
int find_free_elf_slot() {
    for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
        if (!elf_processes[i].active) {
            return i;
        }
    }
    return -1;
}

// Validate ELF header
bool validate_elf_header(const Elf32_Ehdr* ehdr) {
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return false;
    }
    
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        return false;
    }
    
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return false;
    }
    
    if (ehdr->e_type != ET_EXEC) {
        return false;
    }
    
    if (ehdr->e_machine != EM_386) {
        return false;
    }
    
    return true;
}


bool disk_has_password() {
    if (!ahci_base || !current_directory_cluster) return false;
    // Probe raw — directory must be readable before unlock.
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    bool found = (fat32_find_entry(g_disk_password_file, &entry, &sector, &offset) == 0);
    g_fs_encryption_enabled = was_enabled;
    return found;
}
// Kill an ELF process
void kill_elf_process(int slot) {
    if (slot >= 0 && slot < MAX_ELF_PROCESSES && elf_processes[slot].active) {
        ElfProcess& proc = elf_processes[slot];

        // Release the Bochs glue's mapping for this slot BEFORE freeing
        // its backing memory. Without this the glue's SlotState keeps a
        // mem_base pointer into memory we're about to free; the next
        // bochs_activate_slot() on this slot (e.g. a new ELF reusing it)
        // can then dereference that dangling pointer. tick_elf_processes'
        // normal exit path and TerminalWindow::close() both already do
        // this — killelf was the one teardown path that skipped it,
        // which made `killelf` an unsafe way to recover from exactly the
        // runaway/stuck-process situation it exists to handle.
        bochs_release_slot(slot);

        if (proc.memory_base) {
            elf_free_bytes(proc.memory_base);
        }
        if (proc.stack) {
            elf_free_bytes(proc.stack);
        }

        // If a terminal window is still waiting on this slot's input
        // (captured_elf_slot), release it so the prompt comes back
        // instead of the window silently swallowing further keystrokes
        // for a process that no longer exists.
        if (proc.terminal && proc.terminal->get_elf_slot() == slot) {
            proc.terminal->captured_elf_slot = -1;
        }

        proc.active          = false;
        proc.completed        = true;
        proc.cpu_initialized = false;
        proc.memory_base     = nullptr;
        proc.stack           = nullptr;
        proc.memory_size     = 0;
        proc.terminal         = nullptr;
    }
}

// List ELF processes
void list_elf_processes(TerminalWindow* terminal) {
    if (!terminal) return;
    
    terminal->console_print("Active ELF processes:\n");
    bool found = false;
    for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
        if (elf_processes[i].active) {
            char msg[128];
            snprintf(msg, 128, "  Slot %d: entry=0x%x mem=%d KB cmd=%s\n", 
                     i, 
                     elf_processes[i].entry_point,
                     elf_processes[i].memory_size / 1024,
                     elf_processes[i].cmdline);
            terminal->console_print(msg);
            found = true;
        }
    }
    if (!found) {
        terminal->console_print("  (none)\n");
    }
}


// =============================================================================
// DISK PASSWORD SYSTEM
// =============================================================================

static uint32_t simple_hash(const char* str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;
    }
    return hash;
}

static void hash_to_hex(uint32_t hash, char* out) {
    const char* hex = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) {
        out[i] = hex[hash & 0xF];
        hash >>= 4;
    }
    out[8] = '\0';
}
bool disk_check_password(const char* attempt) {
    // Read raw — the password file is always plaintext on disk.
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;
    char* stored = fat32_read_file_as_string(g_disk_password_file);
    g_fs_encryption_enabled = was_enabled;

    if (!stored) return false;

    uint32_t hash = simple_hash(attempt);
    char hex[9];
    hash_to_hex(hash, hex);
    bool match = (strncmp(stored, hex, 8) == 0);
    delete[] stored;

    if (match) fs_crypto_init(attempt);
    return match;
}
bool disk_set_password(const char* password) {
    if (!password || password[0] == '\0') return false;
    if (strlen(password) < 4) return false;

    // 1. Make sure crypto is OFF so the write goes to disk plaintext.
    //    The password file must always be written unencrypted because
    //    disk_has_password() and disk_check_password() probe it raw.
    bool was_enabled = g_fs_encryption_enabled;
    g_fs_encryption_enabled = false;

    // 2. Compute and write the hash record unencrypted.
    uint32_t hash = simple_hash(password);
    char hex[9];
    hash_to_hex(hash, hex);
    bool ok = (fat32_write_file(g_disk_password_file, hex, 8) == 0);

    // 3. Only arm encryption if the write succeeded.
    if (ok) {
        fs_crypto_init(password);
        g_fs_encryption_enabled = true;
    } else {
        g_fs_encryption_enabled = was_enabled;
        fs_crypto_clear();
    }

    return ok;
}
bool disk_remove_password(const char* current_password) {
    if (!disk_check_password(current_password)) return false;

    // Disarm crypto first so the remove operates on the plaintext directory.
    fs_crypto_clear();
    g_fs_encryption_enabled = false;

    fat32_remove_file(g_disk_password_file);
    g_disk_unlocked = false;
    return true;
}


// Guards all disk-touching commands — returns true if access is allowed
bool disk_access_allowed(TerminalWindow* term) {
    if (!disk_has_password()) return true;   // no password set → open
    if (g_disk_unlocked) return true;         // already authenticated this session
    if (term) term->console_print("Disk is locked. Use: unlock <password>\n");
    return false;
}


// --- Terminal command handler ---
void handle_command() {
    int selected_port = 0;
    char cmd_line[120];
    strncpy(cmd_line, current_line, 119);
    cmd_line[119] = '\0';

    char* command = cmd_line;
    while (*command && *command == ' ') {
        command++;
    }

    if (*command == '\0') {
        if (!in_editor) print_prompt();
        return;
    }

    char* args = command;
    while (*args && *args != ' ') {
        args++;
    }
    if (*args) {
        *args = '\0'; 
        args++;       
        while (*args && *args == ' ') {
            args++;
        }
    }

	if (strcmp(command, "help") == 0) {
		console_print("\nCommands: help, clear, version, time, ps, ls, edit, run, exec,\n"
					  "  cd <dir> | cd .. | cd /   -- change directory, pwd, mkdir <name>\n"
					  "  compile, rm, cp, mv, formatfs, chkdsk (/r /f), select_disk,\n"
					  "  setpass, removepass, unlock, busybox, pself, killelf,\n"
					  "  killexec, killrun, aesenc, aesdec, test,\n"
					  "  bochs <elf-file> [args]  -- run ELF in Bochs emulator window\n"
				  "  testelf <elf-file>       -- boot ELF via test module (Phase1/2 + diagnostics)\n"
					  "  cc <file.c> [out]        -- compile C in-kernel via TCC\n"
					  "  hello                   -- shortcut: bochs hello\n"
					  "  reset                   -- shortcut: bochs reset\n"
					  "  (ELF programs can draw graphics -- see bochs_drivers.h's\n"
					  "   gfx_present()/gfx_set_pixel(), or run gfx_demo)\n"
					  "  matrix help             -- NumPy-style arrays + blocked GEMM\n"
					  "  launch <app> | clock | calc | paint | snake | mines\n"
					  "  monitor | inspector | about   -- open desktop apps\n");
	}
	else if (strcmp(command, "bochs") == 0) {
		// Enter Bochs emulator mode in this terminal window. If a
		// filename was given (the documented usage -- see hello_tcc.c's
		// own header comment and the `help` text: "bochs <elf-file>
		// [args]") run it immediately instead of silently discarding
		// the argument and just printing a banner, which is all this
		// branch used to do with anything typed after `bochs`.
		is_emulator_window = true;
		title = "Bochs Emulator";

		char* bochs_fname = nullptr;
		char* bochs_args  = nullptr;
		if (args) {
			char* p = args;
			while (*p == ' ') p++;
			if (*p) {
				// Find the end of the first token BEFORE calling
				// get_arg, which null-terminates the buffer at exactly
				// this boundary -- compute bochs_args first so it
				// already points past that mutation point.
				char* tok_end = p;
				while (*tok_end && *tok_end != ' ') tok_end++;
				char* rest = tok_end;
				while (*rest == ' ') rest++;
				if (*rest) bochs_args = rest;
			}
			bochs_fname = get_arg(args, 0);
		}

		if (!bochs_fname) {
			console_print("=== Bochs i386 CPU emulator ===\n");
			console_print("Just type an ELF filename to run it -- init happens automatically.\n");
		} else {
			console_print("\n");
			int s = load_and_execute_elf(bochs_fname, bochs_args, this);
			if (s >= 0) captured_elf_slot = s;
		}
	}
	else if (strcmp(command, "reset") == 0) {

		bochs_reset_done = true;
		// Run the Bochs CPU reset sequence (test_module_run Phase 1+2)
		// so BX_CPU(0) is fully initialised and the test slab is wiped.
		test_vga_clear();
		g_test_overlay_active = false;
		g_test_overlay_owner  = (void*)this;

		TestSink sink;
		sink.put_line = test_sink_put_line;
		sink.vga_cell = test_sink_vga_cell;
		sink.flush    = test_sink_flush;

		TestResult res;
		res.phase1_ok = 0; res.phase2_ticked = 0;
		res.guest_exit_seen = 0; res.guest_exit_code = 0;
		res.guest_out_len = 0; res.guest_out[0] = 0;

		test_module_run(&sink, &res);

		bochs_reset_all_slots();

		for (int s = 0; s < MAX_ELF_PROCESSES; ++s)
			bochs_register_io_callbacks(s, elf_io_read, elf_io_write, elf_io_exit);

		g_test_overlay_active = false;
		g_test_overlay_owner  = nullptr;

		if (res.phase1_ok && res.guest_exit_seen)
			console_print("reset: OK\n");
		else if (res.phase1_ok)
			console_print("reset: init OK, guest incomplete\n");
		else
			console_print("reset: FAILED\n");
		
	}
	else if (strcmp(command, "testelf") == 0) {
		// Boot a real ELF file from disk through the test module's
		// Phase 1 (BX_CPU init) + Phase 2 (tick) infrastructure, instead
		// of load_and_execute_elf's normal lazy-init path. Useful as a
		// diagnostic: it reuses the same panic-recovery/breadcrumb
		// machinery the `test`/`reset` self-test relies on, with full
		// visibility into init failures, instead of x86_tick's silent
		// per-frame lazy init.
		const char* fname = get_arg(args, 0);
		if (!fname) {
			console_print("Usage: testelf <elf-file>\n");
		} else if ([]{ for (int i = 0; i < MAX_ELF_PROCESSES; ++i)
		                   if (elf_processes[i].active) return true;
		               return false; }()) {
			// testelf shares the same MAX_BOCHS_SLOTS pool as real
			// running ELF processes, hardcodes slot 0 for its own use,
			// and its cleanup calls bochs_reset_all_slots() — which
			// wipes the mapping AND saved CPU snapshot for every slot,
			// not just slot 0. Running it while anything else is live
			// would silently corrupt or kill that process. Refuse
			// instead of doing that quietly.
			console_print("testelf: refusing -- another ELF is currently "
			              "running (use killelf or wait for it to finish)\n");
		} else {
			fat_dir_entry_t entry;
			uint32_t sector = 0, offset = 0;
			if (fat32_find_entry(fname, &entry, &sector, &offset) != 0) {
				console_print("testelf: file not found\n");
			} else {
				char* elfdata = fat32_read_file_as_string(fname);
				if (!elfdata) {
					console_print("testelf: failed to read file\n");
				} else {
					test_vga_clear();
					g_test_overlay_active = false;
					g_test_overlay_owner  = (void*)this;

					TestSink sink;
					sink.put_line = test_sink_put_line;
					sink.vga_cell = test_sink_vga_cell;
					sink.flush    = test_sink_flush;

					TestResult res;
					res.phase1_ok = 0; res.phase2_ticked = 0;
					res.guest_exit_seen = 0; res.guest_exit_code = 0;
					res.guest_out_len = 0; res.guest_out[0] = 0;

					// A real ELF needs far more than the built-in
					// guest's 32-tick budget. 200000 is a soft cap so a
					// genuinely runaway guest can't wedge the terminal
					// forever -- it still blocks the kernel for the
					// duration of the run, same as `reset`/`test`.
					test_module_run_elf(&sink, &res,
						(const unsigned char*)elfdata,
						entry.file_size, 200000);

					delete[] elfdata;

					// Same big-hammer cleanup as `reset`: wipe the test
					// slab's CPU/glue state and re-register the normal
					// per-window ELF I/O callbacks so slot 0 is usable
					// again by the regular load_and_execute_elf path.
					bochs_reset_all_slots();
					for (int s = 0; s < MAX_ELF_PROCESSES; ++s)
						bochs_register_io_callbacks(s, elf_io_read, elf_io_write, elf_io_exit);

					g_test_overlay_active = false;
					g_test_overlay_owner  = nullptr;

					if (!res.phase1_ok)
						console_print("testelf: FAILED (Bochs init)\n");
					else if (res.guest_exit_seen)
						console_print("testelf: guest exited\n");
					else
						console_print("testelf: tick budget exhausted (guest still running)\n");
				}
			}
		}
	}
	else if (strcmp(command, "aesenc") == 0 || strcmp(command, "aesdec") == 0) {
        bool encrypt = strcmp(command, "aesenc") == 0;
        char* key_hex = get_arg(args, 0);
        char* infile = get_arg(args, 1);
        char* outfile = get_arg(args, 2);
        if (!key_hex || !infile || !outfile || strlen(key_hex) != 32) {
            console_print(encrypt ? "Usage: aesenc <32hexkey> <in> <out>\n" : "Usage: aesdec <32hexkey> <in> <out>\n");
            return;
        }
        bool ok = encrypt ? aes_encrypt_file(key_hex, infile, outfile) : aes_decrypt_file(key_hex, infile, outfile);
        console_print(ok ? "AES operation successful.\n" : "AES failed.\n");
    }
	else if (strcmp(command, "select_disk") == 0) {
		g_disk_unlocked = false;
		fs_crypto_clear();                   // wipe key on disk switch
		cmd_list_and_select_disk(args);
		if (disk_has_password())
			console_print("This disk is password protected. Use: unlock <password>\n");
	}

	else if (strcmp(command, "unlock") == 0) {
		if (!disk_has_password()) {
			console_print("No password set. Use: setpass <password>\n");
		} else if (g_disk_unlocked) {
			console_print("Disk already unlocked.\n");
		} else {
			char* pw = get_arg(args, 0);
			if (!pw) {
				console_print("Usage: unlock <password>\n");
			} else if (disk_check_password(pw)) {  // arms crypto internally
				g_disk_unlocked = true;
				console_print("Disk unlocked and decryption armed.\n");
			} else {
				console_print("Wrong password.\n");
			}
		}
	}
	// NOTE: was `if (strcmp(...))` starting a second independent chain;
	// changed to `else if` so commands matched by the first chain (help,
	// aesenc, select_disk, unlock) don't also fall through to the
	// ELF-launch / "command not found" branch at the end.
	else if (strcmp(command, "compile") == 0) {
        cmd_compile(ahci_base, selected_port, get_arg(args, 0));
    }
    // ── cc / tcc — C compiler frontend ───────────────────────────────────
    // cc <source.c> [output]
    //
    // Compilation runs on the HOST via the tcc_glue tool (`make cc`).
    // Inside the kernel this command explains the workflow and, as a
    // convenience, immediately tries to run the ELF if it already exists
    // on the FAT32 disk from a previous host-side `make cc` invocation.
    //
    // Workflow:
    //   1. On the host (before or after booting):
    //        make cc SRC=foo.c          # compiles foo.c → foo on disk.img
    //   2. In this terminal:
    //        cc foo.c                   # (explains the above)
    //        foo                        # runs the compiled ELF via Bochs
    //
    // The reason compilation lives on the host is identical to the reason
    // bochs_glue.so lives there: TCC itself is not a freestanding library
    // and needs malloc, file I/O, and a POSIX environment.
    else if (strcmp(command, "cc")  == 0 ||
             strcmp(command, "tcc") == 0) {
        char* src_arg = get_arg(args, 0);
        char* out_arg = get_arg(args, 1);

        if (!src_arg) {
            console_print("Usage: cc <source.c> [output]\n");
            if (tcc_kernel_version() >= 2) {
                console_print("  Compiles C source from disk to a 32-bit ELF and runs it.\n");
                console_print("  Source must already be on the FAT32 disk (copy via mtools\n");
                console_print("  or write it with the built-in editor if available).\n");
            } else {
                console_print("  In-kernel TCC not linked. Use on the host:\n");
                console_print("      make cc SRC=<file.c>\n");
                console_print("  to compile and inject the ELF into disk.img.\n");
            }
        } else {
            if (tcc_kernel_version() >= 2) {
                // Real in-kernel compilation via libtcc.
                tcc_kernel_cmd_cc(this, src_arg, out_arg);
            } else {
                // Stub path: explain host workflow, auto-run if ELF exists.
                char out_name[64];
                if (out_arg) {
                    strncpy(out_name, out_arg, sizeof(out_name) - 1);
                    out_name[sizeof(out_name) - 1] = '\0';
                } else {
                    strncpy(out_name, src_arg, sizeof(out_name) - 1);
                    out_name[sizeof(out_name) - 1] = '\0';
                    for (int _i = (int)strlen(out_name)-1; _i >= 0; _i--)
                        if (out_name[_i] == '.') { out_name[_i] = '\0'; break; }
                }
                fat_dir_entry_t _elf_entry;
                uint32_t _elf_sec = 0, _elf_off = 0;
                bool _elf_exists =
                    (fat32_find_entry(out_name, &_elf_entry, &_elf_sec, &_elf_off) == 0);

                console_print("cc: in-kernel TCC not available. On the host run:\n");
                console_print("        make cc SRC="); console_print(src_arg);
                if (out_arg) { console_print(" OUT="); console_print(out_arg); }
                console_print("\n");
                
            }
        }
    }
	 else if (strcmp(command, "pself") == 0) {
			// List ELF processes
			list_elf_processes(this);
    } else if (strcmp(command, "killelf") == 0) {
        // Kill an ELF process
        char* arg = get_arg(args, 0);
        if (arg) {
            int slot = simple_atoi(arg);
            kill_elf_process(slot);
            console_print("ELF process killed\n");
        } else {
            console_print("Usage: killelf <slot>\n");
        }
    }
	else if (strcmp(command, "ps") == 0) {
        list_run_processes();
        list_exec_processes();
    }
    else if (strcmp(command, "killrun") == 0) {
        kill_run_process(simple_atoi(get_arg(args, 0)));
    }
    else if (strcmp(command, "killexec") == 0) {
        kill_exec_process(simple_atoi(get_arg(args, 0)));
    }
	
	else if (strcmp(command, "setpass") == 0) {
		// Allowed even when locked so the first password can be set,
		// but changing an existing password requires unlock first.
		if (disk_has_password() && !g_disk_unlocked) {
			console_print("Disk locked. Unlock before changing password.\n");
		} else {
			char* pw = get_arg(args, 0);
			if (!pw || strlen(pw) < 4) {
				console_print("Usage: setpass <password>  (min 4 chars)\n");
			} else {
				if (disk_set_password(pw)) {
					g_disk_unlocked = true; // creator is implicitly unlocked
					console_print("Password set. Disk is now protected.\n");
				} else {
					console_print("Failed to write password file.\n");
				}
			}
		}
	}
	else if (strcmp(command, "removepass") == 0) {
		char* pw = get_arg(args, 0);
		if (!pw) {
			console_print("Usage: removepass <current_password>\n");
		} else if (disk_remove_password(pw)) {
			g_disk_unlocked = false; // reset session state
			console_print("Password removed. Disk is now open.\n");
		} else {
			console_print("Wrong password.\n");
		}
	}
    else if (strcmp(command, "clear") == 0) { line_count = 0; memset(buffer, 0, sizeof(buffer)); }
    else if (strcmp(command, "ls") == 0) { fat32_list_files(); }
    else if (strcmp(command, "cd") == 0) {
        char* target = get_arg(args, 0);
        const char* dest = (target && *target) ? target : "/"; // bare 'cd' -> root
        uint32_t new_cluster;
        char new_path[256];
        bool not_a_dir = false;
        if (fat32_resolve_path(dest, current_directory_cluster, current_directory_path,
                                &new_cluster, new_path, sizeof(new_path), &not_a_dir)) {
            current_directory_cluster = new_cluster;
            strncpy(current_directory_path, new_path, 255);
            current_directory_path[255] = '\0';
        } else if (not_a_dir) {
            console_print("cd: not a directory: "); console_print(dest); console_print("\n");
        } else {
            console_print("cd: no such directory: "); console_print(dest); console_print("\n");
        }
    }
    else if (strcmp(command, "pwd") == 0) {
        console_print(current_directory_path);
        console_print("\n");
    }
    else if (strcmp(command, "mkdir") == 0) {
        char* name = get_arg(args, 0);
        if (!name) {
            console_print("Usage: mkdir <name>\n");
        } else if (fat32_mkdir(name) == 0) {
            console_print("Directory created.\n");
        } else {
            fat_dir_entry_t existing;
            if (fat32_find_entry_in(current_directory_cluster, name, &existing) == 0) {
                console_print((existing.attr & FAT_ATTR_DIRECTORY)
                              ? "mkdir: a directory named that already exists\n"
                              : "mkdir: a FILE (not a directory) named that already exists\n");
            } else {
                console_print("mkdir: failed (disk full?)\n");
            }
        }
    }
    else if (strcmp(command, "edit") == 0) {
        char* filename = get_arg(args, 0);
        if(filename) {
            strncpy(edit_filename, filename, 127);
            edit_filename[127] = '\0';
            in_editor = true;
            edit_current_line = 0;
            edit_cursor_col = 0;
            edit_scroll_offset = 0;
            char* content = fat32_read_file_as_string_path(filename);

            // Seed with a single empty line; editor_insert_line_at() grows
            // the array as wrapped segments are appended below.
            //
            // The old loader just strncpy()'d each raw line (split only on
            // '\n') straight into a fixed 119-char slot. That silently
            // truncated anything past 119 chars, and — the real bug —
            // never wrapped lines that were under 119 chars but still
            // wider than the editor's visible column width, so on open
            // they were drawn straight off the right edge of the window
            // instead of wrapping the way they would if you'd typed them.
            // Word-wrap on load exactly like the live typing path does,
            // using the same EDITOR_WRAP_WIDTH, so a loaded file looks
            // identical to one typed in by hand.
            edit_lines = new char*[1];
            edit_lines[0] = new char[120];
            memset(edit_lines[0], 0, 120);
            edit_line_count = 1;

            if (content) {
                bool first_segment_used = false;
                char* line_start = content;
                char* p = content;
                for (;;) {
                    bool at_end = (*p == '\0');
                    if (*p == '\n' || at_end) {
                        char saved = *p;
                        *p = '\0';

                        // Word-wrap this raw (newline-delimited) line into
                        // one or more editor lines at EDITOR_WRAP_WIDTH
                        // columns. Runs at least once even for a blank
                        // line, so blank lines in the file are preserved.
                        char* seg = line_start;
                        do {
                            int seg_len = (int)strlen(seg);
                            int take = seg_len;
                            if (seg_len > EDITOR_WRAP_WIDTH) {
                                take = find_wrap_pos(seg, EDITOR_WRAP_WIDTH);
                                if (take <= 0) take = EDITOR_WRAP_WIDTH;
                            }

                            char saved_c = seg[take];
                            seg[take] = '\0';

                            if (!first_segment_used) {
                                strncpy(edit_lines[0], seg, 119);
                                first_segment_used = true;
                            } else {
                                editor_insert_line_at(edit_line_count, seg);
                            }

                            seg[take] = saved_c;
                            seg += take;
                            while (*seg == ' ' || *seg == '\t') seg++;
                        } while (*seg);

                        *p = saved;
                        if (at_end) break;
                        line_start = p + 1;
                        p = line_start;
                    } else {
                        p++;
                    }
                }
                delete[] content;
            }
        } else {
            console_print("Usage: edit \"<filename>\"\n");
        }
    }
    
    else if (strcmp(command, "rm") == 0) { 
        char* filename = get_arg(args, 0); 
        if(filename) { 
            if(fat32_remove_file(filename) == 0) 
                console_print("File removed.\n"); 
            else 
                console_print("Failed to remove file.\n");
        } else { 
            console_print("Usage: rm \"<filename>\"\n");
        }
    }
    else if (strcmp(command, "cp") == 0) {
        char args_for_src[120];
        strncpy(args_for_src, args, 119);
        char* src = get_arg(args_for_src, 0);

        char args_for_dest[120];
        strncpy(args_for_dest, args, 119);
        char* dest = get_arg(args_for_dest, 1);

        if (!src || !dest) {
            console_print("Usage: cp \"<source>\" \"<dest>\"\n");
        } else if (fat32_copy_file_path(src, dest) == 0) {
            console_print("Copied.\n");
        } else {
            console_print("Copy failed. (source not found, or it's a directory)\n");
        }
    }
    else if (strcmp(command, "mv") == 0) {
        char args_for_src[120];
        strncpy(args_for_src, args, 119);
        char* src = get_arg(args_for_src, 0);

        char args_for_dest[120];
        strncpy(args_for_dest, args, 119);
        char* dest = get_arg(args_for_dest, 1);

        if(!src || !dest) { 
            console_print("Usage: mv \"<source>\" \"<dest>\"\n"); 
        } else {
            if(fat32_move_file_path(src, dest) == 0) {
                console_print("Moved.\n");
            } else {
                console_print("Failed. (Source not found or destination exists).\n");
            }
        }
    }
    // CORRECT — format always writes plaintext; encryption is a post-format concern:
	else if (strcmp(command, "formatfs") == 0) {
		bool saved = g_fs_encryption_enabled;
		g_fs_encryption_enabled = false;   // format always writes raw
		fat32_format();
		g_fs_encryption_enabled = saved;
	}
    else if (strcmp(command, "chkdsk") == 0) {
        char* args_copy = new char[120];
        strncpy(args_copy, args, 119);
        args_copy[119] = '\0';
        
        bool fix = false;
        bool fullscan = false;
        
        if (strstr(args_copy, "/f") || strstr(args_copy, "/F")) {
            fix = true;
        }
        if (strstr(args_copy, "/r") || strstr(args_copy, "/R")) {
            fix = true;
            fullscan = true;
        }
        
        chkdsk(fix, true);
        
        if (fullscan) {
            chkdsk_full_scan(fix);
        }
        
        delete[] args_copy;
    }
	
    else if (strcmp(command, "time") == 0) { 
        RTC_Time t = read_rtc(); 
        char buf[64]; 
        snprintf(buf, 64, "%d:%d:%d %d/%d/%d\n", t.hour, t.minute, t.second, t.day, t.month, t.year); 
        console_print(buf); 
    }
    else if (strcmp(command, "version") == 0) { console_print("RTOS++ v1.0 - Robust Parsing\n"); }

    // ── 'bochs <elf>' command ─────────────────────────────────────────────
    // Explicit front-end for running a FAT32 ELF under the Bochs x86
    // emulator.  Always spawns a dedicated emulator TerminalWindow (like
    // the fall-through branch) so the user gets a named window regardless
    // of whether they typed from a shell or an emulator window.
    //
    //   bochs <filename>          — run ELF with no args
    //   bochs <filename> [args…]  — run ELF and pass remaining tokens as args
    //
    // The kernel's Bochs self-test (test_module_run) is NOT re-run here;
    // the CPU is already initialised by kernel_main.  The new emulator
    // window picks up from the lazy-init path in x86_tick exactly the same
    // way as every other ELF launch in this kernel.
    

    // ===================================================================
    // PATCH: matrix array store + desktop suite commands
    // ===================================================================

    // ----- matrix --------------------------------------------------------
    //   matrix create <name> <rows> <cols> [perms=rwx]
    //   matrix list                       (alias: matrix ls)
    //   matrix show <name>
    //   matrix gemm <A> <B> <C>           (C = A . B, blocked tile=4x4)
    //   matrix perms <name> <rwxt>
    //   matrix rm <name>
    else if (strcmp(command, "matrix") == 0) {
        TerminalWindow* term = this;
        char* sub = get_arg(args, 0);
        if (!sub || strcmp(sub, "help") == 0) {
            console_print(
                "matrix: NumPy-style storage arrays + blocked GEMM\n"
                "  matrix create <name> <rows> <cols> [perms=rwx]\n"
                "  matrix list\n"
                "  matrix show   <name>\n"
                "  matrix gemm   <A> <B> <C>      # C = A . B  (i32, tile 4x4)\n"
                "  matrix perms  <name> <rwxt>    # set capability bits\n"
                "  matrix rm     <name>\n"
                "perms: r=read w=write x=kernel-exec t=transmit\n");
            return;
        }
        // append ".npa" if missing
        auto with_ext = [](const char* n, char* out, int cap) -> const char* {
            if (!n || !*n) return nullptr;
            int len = 0; while (n[len] && len < cap - 5) len++;
            bool has_ext = false;
            if (len >= 4 && n[len-4] == '.' &&
                n[len-3] == 'n' && n[len-2] == 'p' && n[len-1] == 'a') has_ext = true;
            for (int i = 0; i < len; ++i) out[i] = n[i];
            if (!has_ext) { out[len++]='.'; out[len++]='n'; out[len++]='p'; out[len++]='a'; }
            out[len] = '\0';
            return out;
        };

        if (strcmp(sub, "create") == 0) {
            char* name = get_arg(args, 1);
            char* rs   = get_arg(args, 2);
            char* cs   = get_arg(args, 3);
            char* ps   = get_arg(args, 4);
            if (!name || !rs || !cs) {
                console_print("Usage: matrix create <name> <rows> <cols> [perms=rwx]\n"); return;
            }
            char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
            uint16_t perms = parse_perms(ps);
            int rc = npa_create(fn, (uint32_t)simple_atoi(rs), (uint32_t)simple_atoi(cs), perms, 0);
            if (rc == 0) { console_print("matrix: created "); console_print(fn); console_print("\n"); }
            else { console_print("matrix: create failed (rc=");
                   char b[8]; int_to_string(rc, b); console_print(b); console_print(")\n"); }
            return;
        }
        if (strcmp(sub, "list") == 0 || strcmp(sub, "ls") == 0) {
            const char* names[] = { "A.npa", "B.npa", "C.npa", "D.npa", "E.npa", "F.npa", 0 };
            bool any = false;
            for (int i = 0; names[i]; ++i) {
                ArrayHeader h; void* d = nullptr;
                if (npa_load(names[i], &h, &d) == 0) {
                    npa_print_header(npa_term_print, term, names[i], h);
                    delete[] (uint8_t*)d;
                    any = true;
                }
            }
            if (!any) console_print("matrix: no arrays found (try: matrix create A 8 8)\n");
            return;
        }
        if (strcmp(sub, "show") == 0) {
            char* name = get_arg(args, 1);
            if (!name) { console_print("Usage: matrix show <name>\n"); return; }
            char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
            ArrayHeader h; void* d = nullptr;
            int rc = npa_load(fn, &h, &d);
            if (rc != 0) { console_print("matrix: load failed\n"); return; }
            if (!npa_has(h, NPA_R)) {
                console_print("matrix: R denied on "); console_print(fn); console_print("\n");
                delete[] (uint8_t*)d; return;
            }
            npa_print_header(npa_term_print, term, fn, h);
            npa_print_data  (npa_term_print, term, h, d, 8, 8);
            delete[] (uint8_t*)d;
            return;
        }
        if (strcmp(sub, "gemm") == 0) {
            char* a = get_arg(args, 1), *b = get_arg(args, 2), *c = get_arg(args, 3);
            if (!a || !b || !c) { console_print("Usage: matrix gemm <A> <B> <C>\n"); return; }
            char ab[64], bb[64], cb[64];
            const char* fa = with_ext(a, ab, sizeof(ab));
            const char* fb = with_ext(b, bb, sizeof(bb));
            const char* fc = with_ext(c, cb, sizeof(cb));
            int rc = npa_gemm(fa, fb, fc);
            if (rc == 0) { console_print("matrix: gemm OK -> "); console_print(fc); console_print("\n"); }
            else {
                console_print("matrix: gemm failed (rc=");
                char bf[8]; int_to_string(rc, bf); console_print(bf);
                console_print(")  -20=R-denied -21=shape -22=dtype -23=W-denied -24=C-shape\n");
            }
            return;
        }
        if (strcmp(sub, "perms") == 0) {
            char* name = get_arg(args, 1), *ps2 = get_arg(args, 2);
            if (!name || !ps2) { console_print("Usage: matrix perms <name> <rwxt>\n"); return; }
            char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
            ArrayHeader h; void* d = nullptr;
            if (npa_load(fn, &h, &d) != 0) { console_print("matrix: load failed\n"); return; }
            h.perms = parse_perms(ps2);
            h.ver_num++;
            int rc = npa_save(fn, &h, d);
            delete[] (uint8_t*)d;
            console_print(rc == 0 ? "matrix: perms updated\n" : "matrix: save failed\n");
            return;
        }
        if (strcmp(sub, "rm") == 0) {
            char* name = get_arg(args, 1);
            if (!name) { console_print("Usage: matrix rm <name>\n"); return; }
            char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
            fat32_remove_file(fn);
            console_print("matrix: removed "); console_print(fn); console_print("\n");
            return;
        }
        console_print("matrix: unknown subcommand. Try `matrix help`.\n");
    }
    // ----- desktop suite launchers --------------------------------------
    else if (strcmp(command, "launch") == 0 || strcmp(command, "open") == 0) {
        char* app = get_arg(args, 0);
        if (!app) {
            console_print("Usage: launch <app>\nApps:");
            for (const char** nm = desktop_app_names(); *nm; ++nm) {
                console_print(" "); console_print(*nm);
            }
            console_print("\n");
            return;
        }
        if (!desktop_launch(app, &wm)) {
            console_print("launch: unknown app '"); console_print(app); console_print("'\n");
        }
    }
    else if (strcmp(command, "clock")      == 0) { desktop_launch("clock",   &wm); }
    else if (strcmp(command, "calc")       == 0
          || strcmp(command, "calculator") == 0) { desktop_launch("calc",    &wm); }
    else if (strcmp(command, "paint")      == 0) { desktop_launch("paint",   &wm); }
    else if (strcmp(command, "snake")      == 0) { desktop_launch("snake",   &wm); }
    else if (strcmp(command, "mines")      == 0
          || strcmp(command, "minesweeper")== 0) { desktop_launch("mines",   &wm); }
    else if (strcmp(command, "monitor")    == 0
          || strcmp(command, "sysmon")     == 0
          || strcmp(command, "top")        == 0) { desktop_launch("monitor", &wm); }
    else if (strcmp(command, "inspector")  == 0) { desktop_launch("matrix",  &wm); }
    else if (strcmp(command, "about")      == 0) { desktop_launch("about",   &wm); }

    // Fall-through: try to handle 'command' as an ELF file from FAT32.
    // The ELF runs inside the Bochs CPU emulator via x86_tick / cpu_loop.
    //
    // This used to require the user to type `bochs` (enter emulator
    // mode) and then `reset` (force-run the Bochs init/self-test
    // sequence) before an ELF filename would actually do anything.
    // kernel_run_global_ctors_once() now guarantees BX_CPU(0)/bx_mem
    // are constructed before kernel_main ever reaches init_elf_system(),
    // and init_elf_system() already registers IO callbacks for every
    // slot at boot — so no per-window init is actually required for
    // correctness here. (bochs_reset_done used to also gate a call to
    // bochs_reset_all_slots() here, but that call is GLOBAL — it wipes
    // every slot's mapping and CPU snapshot, not just this window's —
    // so doing it on a per-window "first ELF run" basis meant any
    // window's first launch could silently kill every other window's
    // already-running ELF process. Removed; nothing here actually
    // needed it.)
    else {

        is_emulator_window = true;
        title = "Bochs Emulator";

        // Run the ELF in-place; output flows to this window's
        // console_print via the elf_io_write callback chain.
	console_print("\n");
        int s = load_and_execute_elf(command, args, this);
        if (s >= 0) captured_elf_slot = s;
    }

    if(!in_editor) print_prompt();
}
int load_and_execute_elf(const char* filename, const char* args, TerminalWindow* terminal) {
    char* elfdata = fat32_read_file_as_string_path(filename);
    if (!elfdata) {
        if (terminal) terminal->console_print("Failed to read ELF file\n");
        return -1;
    }

    int result = -1;
    uint8_t* mem = nullptr;
    uint8_t* stack = nullptr;
    ElfProcess* proc = nullptr;
    int slot = -1;

    do {
        fat_dir_entry_t entry;
        if (fat32_find_entry_path(filename, &entry) != 0) {
            if (terminal) terminal->console_print("ELF: directory entry not found\n");
            break;
        }

        Elf32_Ehdr ehdr;
        memcpy(&ehdr, elfdata, sizeof(Elf32_Ehdr));
        if (!validate_elf_header(&ehdr)) {
            if (terminal) terminal->console_print("Invalid ELF file\n");
            break;
        }

        Elf32_Phdr* phdr = (Elf32_Phdr*)(elfdata + ehdr.e_phoff);
        uint32_t filesize = entry.file_size;

        slot = find_free_elf_slot();
        if (slot < 0) {
            if (terminal) terminal->console_print("No free ELF slot\n");
            break;
        }

        proc = &elf_processes[slot];
        *proc = ElfProcess();
        proc->terminal = terminal;
        // ── Scrub per-slot I/O ring buffers ──────────────────────────────
        // `*proc = ElfProcess()` value-initialises POD members, but the
        // 512-byte inbuf and 4096-byte outbuf char arrays are NOT in the
        // struct's default initialiser list and therefore retain whatever
        // bytes the previous run left in them when this slot is reused.
        // The ring-buffer HEAD/TAIL indices get reset to 0 by the line
        // above (they have default initialisers), so the stale bytes are
        // not directly "readable" via pop_input/pop_output — but they
        // remain reachable through any code path that reads inbuf[]
        // beyond the wrap (e.g. snprintf-style buffer dumps, or a guest
        // doing speculative IN-port reads). They are also a forensic
        // trip-hazard when the head/tail get out of sync due to an
        // unrelated bug — the "phantom" bytes look like real input.
        //
        // Empirically the bug manifested as the third+ in-place run of
        // `hello` in the same emulator window producing
        // "HELLO WOHELLO WO..." loops with the user's typed "hello"
        // prefix concatenated to the guest output. The kernel-side
        // teardown in tick_elf_processes was freeing memory_base/stack
        // and calling bochs_reset_all_slots(), but never wiping the
        // input/output ring buffers — so when the same slot was reused,
        // it carried forward bytes from the previous run's interaction.
        // Zero-fill makes slot reuse architecturally identical to
        // first-time use.
        for (int _b = 0; _b < INBUFSIZE;  ++_b) proc->inbuf[_b]  = 0;
        for (int _b = 0; _b < OUTBUFSIZE; ++_b) proc->outbuf[_b] = 0;
        proc->in_head = proc->in_tail = proc->out_head = proc->out_tail = 0;
        if (args) {
            strncpy(proc->cmdline, args, sizeof(proc->cmdline) - 1);
            proc->cmdline[sizeof(proc->cmdline) - 1] = 0;
        }

        bool found_load = false;
        uint32_t minvaddr = 0xFFFFFFFFu;
        uint32_t maxvaddr = 0;
        bool phdr_bad = false;

        for (int i = 0; i < ehdr.e_phnum; i++) {
            if (phdr[i].p_type != PT_LOAD) continue;
            found_load = true;
            if (phdr[i].p_memsz < phdr[i].p_filesz) { phdr_bad = true; break; }
            if (phdr[i].p_offset + phdr[i].p_filesz > filesize) { phdr_bad = true; break; }
            if (phdr[i].p_vaddr < minvaddr) minvaddr = phdr[i].p_vaddr;
            uint32_t end = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (end > maxvaddr) maxvaddr = end;
        }

        if (phdr_bad) {
            if (terminal) terminal->console_print("ELF: malformed program header (memsz/filesz/offset)\n");
            break;
        }
        if (!found_load) {
            if (terminal) terminal->console_print("ELF: no PT_LOAD segment found\n");
            break;
        }
        if (maxvaddr <= minvaddr) {
            if (terminal) terminal->console_print("ELF: empty or inverted load range\n");
            break;
        }

        uint32_t imgsize = maxvaddr - minvaddr;
        if (imgsize == 0 || imgsize > 6 * 1024 * 1024) {
            if (terminal) terminal->console_print("ELF: image size out of range (0 or >6MB)\n");
            break;
        }

        // Reserve a dead-zone buffer offset before the real image so
        // bochs_set_process_memory's table injection (GDT/IDT/stub,
        // written into the first ~0x900 bytes of whatever buffer it's
        // given) can NEVER land on the program's own code -- regardless
        // of whether the ELF was linked with one of the project's
        // special "slab_reserved" linker scripts (hello.ld/guest.ld/
        // tcc_guest.ld) or with a normal toolchain that knows nothing
        // about this kernel's memory layout. Without this, any ELF
        // whose lowest PT_LOAD segment lands at buffer offset 0 -- which
        // is every ELF, unless its own linker script manually pads --
        // has its first instructions silently corrupted before it ever
        // runs. vaddr_base shifts down by the same RESERVE amount, so
        // the guest-visible absolute address of the real image (and
        // therefore every address the compiler/linker baked into the
        // program) is completely unchanged -- only the underlying
        // buffer layout moves.
        const uint32_t ELF_SLOT_RESERVE = 0x0000;

        // Guard against unsigned underflow: `minvaddr - ELF_SLOT_RESERVE`
        // below silently wraps to a value near 0xFFFFFFFF whenever an ELF's
        // lowest PT_LOAD vaddr is less than ELF_SLOT_RESERVE (0x1000) —
        // e.g. a stale build predating tcc_guest.ld/guest.ld's leading-page
        // reservation, or any toolchain invocation that didn't apply one of
        // this project's slab-aware linker scripts. Left unchecked, the
        // wrapped vaddr_base (e.g. 0xFFFFF000) is then handed straight to
        // bochs_set_process_memory/disk_guest_ptr as this process's guest-
        // physical window base, so EVERY address the guest legitimately
        // owns (which is small, since the program itself links near 0)
        // reads as "before vaddr_base" and gets rejected — the guest keeps
        // running (its own code/data addressing never depended on
        // vaddr_base), but host-side helpers like the disk mailbox can no
        // longer resolve any pointer the guest hands them. Catch it here
        // instead of producing that hard-to-diagnose failure mode deep
        // into execution.
        if (minvaddr < ELF_SLOT_RESERVE) {
            if (terminal) terminal->console_print(
                "ELF: load address too low (must be >= 0x1000) -- "
                "rebuild with the project's guest linker script\n");
            break;
        }

        uint32_t memsize = imgsize + ELFHEAPSIZE + ELF_SLOT_RESERVE;
        if (memsize > 6 * 1024 * 1024) {
            if (terminal) terminal->console_print("ELF: image+heap exceeds 6MB limit\n");
            break;
        }


        mem = elf_alloc_bytes(memsize);
        if (!mem) {
            if (terminal) terminal->console_print("ELF: out of memory (image)\n");
            break;
        }
        memset(mem, 0, memsize);
        proc->memory_base = mem;
        proc->memory_size = memsize;
        proc->vaddr_base = minvaddr - ELF_SLOT_RESERVE;
        proc->vaddr_end = maxvaddr;

        bool copy_bad = false;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            if (phdr[i].p_type != PT_LOAD) continue;
            uint32_t dstoff = ELF_SLOT_RESERVE + (phdr[i].p_vaddr - minvaddr);
            if (dstoff + phdr[i].p_filesz > memsize) { copy_bad = true; break; }
            memcpy(mem + dstoff, elfdata + phdr[i].p_offset, phdr[i].p_filesz);
            if (phdr[i].p_memsz > phdr[i].p_filesz) {
                memset(mem + dstoff + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);
            }
        }
        if (copy_bad) {
            if (terminal) terminal->console_print("ELF: segment offset out of bounds\n");
            break;
        }

        stack = elf_alloc_bytes(ELFSTACKSIZE);
        if (!stack) {
            if (terminal) terminal->console_print("ELF: out of memory (stack)\n");
            break;
        }
        memset(stack, 0, ELFSTACKSIZE);
        proc->stack = stack;

        proc->entry_point = ehdr.e_entry;
        proc->eip = proc->entry_point;
        // ESP sits at the TOP of the slab, growing down. The previous
        // formula was `vaddr_base + memory_size - ELFHEAPSIZE - 16`,
        // which evaluated to `vaddr_base + imgsize - 16` — i.e. just
        // BELOW the end of the loaded image, INSIDE .rodata/.data.
        // For a small hello-world that mostly worked because only a
        // handful of pushes happened before the program exited, but
        // it was timing/luck dependent: the first push of %ebp at
        // [esp-4] could clobber whatever was at slab offset
        // imgsize-20, and a longer or differently-laid-out program
        // could see the program's own data corrupted by the stack.
        //
        // Correct layout (slab grows up; addresses increase →):
        //     [ image (text/rodata/data/bss) ][ heap/stack arena ]
        //     ^vaddr_base                    ^brk                ^ESP
        // The brk grows up from end-of-image; ESP grows down from the
        // top. They share the ELFHEAPSIZE-byte arena and collide only
        // if the program both heap-allocates a lot AND nests deep.
        // The dedicated 64 KB `stack` allocation (proc->stack) is
        // historical scratch — it is NOT wired to ESP.
        proc->esp = proc->vaddr_base + proc->memory_size - 16;
        proc->active = true;
        proc->cpu_initialized = false;
        proc->waiting_for_input = false;
        proc->completed = false;
        proc->exit_code = 0;

        result = slot;
    } while (0);

    if (result < 0) {
        if (proc) {
            if (proc->stack) { elf_free_bytes(proc->stack); proc->stack = nullptr; }
            if (proc->memory_base) { elf_free_bytes(proc->memory_base); proc->memory_base = nullptr; }
            proc->active = false;
            proc->cpu_initialized = false;
            proc->waiting_for_input = false;
            proc->completed = false;
            proc->exit_code = 0;
            proc->memory_size = 0;
            proc->entry_point = 0;
            proc->vaddr_base = 0;
            proc->vaddr_end = 0;
            proc->esp = 0;
            proc->eip = 0;
            proc->cmdline[0] = 0;
        }
    }

    delete[] elfdata;
    return result;
}


public:
    // Public wrapper so tcc_kernel.cpp's bridge can launch an ELF without
    // needing access to the private load_and_execute_elf directly.
    int exec_elf(const char* filename, const char* args) {
        return load_and_execute_elf(filename, args, this);
    }

    // is_emulator_window=true marks this terminal as a window that was
    // spawned specifically to host a Bochs-emulated ELF. Used by
    // handle_command()'s fall-through branch to decide whether to run an
    // unknown ELF *in-place* (we are the emulator window) or to *spawn a
    // fresh emulator window* (we are an ordinary shell).
    TerminalWindow(int x, int y, const char* startup_command = nullptr,
                   bool emulator_mode = false)
        : Window(x, y, 640, 400, emulator_mode ? "Bochs Emulator" : "Terminal"),
          line_count(0), line_pos(0), in_editor(false),
          edit_lines(nullptr), edit_line_count(0), edit_current_line(0),
          edit_cursor_col(0), edit_scroll_offset(0),
          prompt_visual_lines(0),
          is_emulator_window(emulator_mode) {
        memset(buffer, 0, sizeof(buffer));
        current_line[0] = '\0';
        private_startup_cmd[0] = '\0';
        if (startup_command) {
            strncpy(private_startup_cmd, startup_command, 255);
            private_startup_cmd[255] = '\0';
        }

        // Stable ID for this window's taskbar button. Unlike its index in
        // WindowManager::windows[] (which gets reshuffled every time a
        // window is focused — see set_focus()), this never changes, so
        // the terminal's taskbar button stays in the same place for its
        // whole lifetime instead of jumping around as windows are clicked.
        static int s_next_term_id = 1;
        term_id = s_next_term_id++;

        // Print a banner in the emulator window so it's obvious to the
        // user that this is the Bochs CPU emulator booting their ELF, not
        // a normal shell. The banner is queued onto the terminal buffer
        // before the auto-startup command runs on the next update().
        if (emulator_mode) {
            console_print("=== Bochs i386 CPU emulator ===\n");
            console_print("Loading ELF and entering protected mode...\n");
        }

        update_prompt_display(); // Show the initial prompt
    }
    bool is_emulator_window = false;
    bool bochs_reset_done   = false;  // reset runs once per window
    int captured_elf_slot = -1;
    int term_id = -1;
    int get_elf_slot() const override { return captured_elf_slot; }
    int get_taskbar_id() const override { return term_id; }

    // Screen-space rect the guest's gfx canvas was actually drawn into
    // on the most recent draw() call (see the "Guest graphics overlay"
    // block below) — cached there every frame so the mouse ABI can
    // convert screen coordinates to canvas-local ones without redoing
    // the centre/clip math itself. gfx_rect_valid is false whenever
    // this window isn't currently showing a live gfx frame (text mode,
    // editor, or no guest gfx frame present at all).
    int  gfx_rect_x = 0, gfx_rect_y = 0, gfx_rect_w = 0, gfx_rect_h = 0;
    bool gfx_rect_valid = false;

    bool gfx_hit_test(int mx, int my, int* local_x, int* local_y) const override {
        if (!gfx_rect_valid) return false;
        int lx = mx - gfx_rect_x;
        int ly = my - gfx_rect_y;
        if (lx < 0 || ly < 0 || lx >= gfx_rect_w || ly >= gfx_rect_h) return false;
        *local_x = lx;
        *local_y = ly;
        return true;
    }

    void close() override {
        // If this window owned the Bochs self-test overlay, relinquish it
        // so g_test_overlay_owner never dangles after we are deleted.
        if (g_test_overlay_owner == (void*)this) {
            g_test_overlay_owner  = nullptr;
            g_test_overlay_active = false;
        }
        // Kill the attached ELF process so it disappears from the taskbar.
        // Also release the Bochs glue slot and free the slab/stack to avoid
        // dangling pointers in the memory-handler table and memory leaks.
        if (captured_elf_slot >= 0 && captured_elf_slot < MAX_ELF_PROCESSES) {
            ElfProcess& proc = elf_processes[captured_elf_slot];
            proc.active    = false;
            proc.completed = true;
            proc.terminal  = nullptr;
            // Unregister the Bochs memory handlers for this slot before
            // freeing the slab — otherwise the glue holds a dangling
            // mem_base pointer that any future activate_slot could deref.
            bochs_release_slot(captured_elf_slot);
            if (proc.memory_base) { elf_free_bytes(proc.memory_base); proc.memory_base = nullptr; }
            if (proc.stack)       { elf_free_bytes(proc.stack);       proc.stack       = nullptr; }
            proc.memory_size     = 0;
            proc.cpu_initialized = false;
        }
        captured_elf_slot = -1;
        is_closed = true;
    }

    ~TerminalWindow() { 
        if(edit_lines) {
            for(int i = 0; i < edit_line_count; i++) delete[] edit_lines[i];
            delete[] edit_lines;
        }
    }

    // Map a VGA attribute byte (bg<<4 | fg) to a framebuffer RGB color.
    // Only the foreground nibble drives the glyph color; we use a compact
    // 16-entry CGA-style palette. The background nibble tints the row.
    static uint32_t test_vga_palette(uint8_t nibble) {
        static const uint32_t pal[16] = {
            0x000000, 0x0000AA, 0x00AA00, 0x00AAAA,
            0xAA0000, 0xAA00AA, 0xAA5500, 0xAAAAAA,
            0x555555, 0x5555FF, 0x55FF55, 0x55FFFF,
            0xFF5555, 0xFF55FF, 0xFFFF55, 0xFFFFFF
        };
        return pal[nibble & 0x0F];
    }

    // Draw the three g_test_vga[] rows at the top of the content area.
    // Returns the vertical pixel offset the terminal text should shift by
    // so it sits below the overlay.
    int render_test_overlay() {
        const int cell_w  = 8;             // font glyph width
        const int row_h   = 10;            // overlay row height
        const int top     = y + 28;        // just under the titlebar
        const int max_col = (w - 10) / cell_w < 80 ? (w - 10) / cell_w : 80;

        for (int r = 0; r < 3; ++r) {
            int row_y = top + r * row_h;
            // Tint strip: use the background nibble of the row's first
            // non-blank cell (cells in a row share a background).
            uint8_t bg_nib = 0;
            for (int c = 0; c < max_col; ++c) {
                if (g_test_vga[r][c].ch != ' ') {
                    bg_nib = (g_test_vga[r][c].attr >> 4) & 0x0F;
                    break;
                }
            }
            draw_rect_filled(x + 4, row_y, max_col * cell_w, row_h,
                             test_vga_palette(bg_nib));
            for (int c = 0; c < max_col; ++c) {
                char ch = g_test_vga[r][c].ch;
                if (ch == ' ' || ch == 0) continue;
                uint32_t fg = test_vga_palette(g_test_vga[r][c].attr & 0x0F);
                char s[2] = { ch, 0 };
                draw_string(s, x + 5 + c * cell_w, row_y + 1, fg);
            }
        }
        return 3 * row_h + 2;              // shift terminal text down
    }

    void draw() override {
        if (!has_focus && is_closed) return;
        if (is_minimized) return; // hidden but still "running" — see taskbar button

        using namespace ColorPalette;
        
        uint32_t titlebar_color = has_focus ? TITLEBAR_ACTIVE : TITLEBAR_INACTIVE;
        draw_rect_filled(x, y, w, 25, titlebar_color);
        // Show slot info in titlebar when running an ELF
        if (captured_elf_slot >= 0) {
            char ttl[48];
            ttl[0]='T'; ttl[1]='e'; ttl[2]='r'; ttl[3]='m'; ttl[4]=' ';
            ttl[5]='['; ttl[6]='S'; ttl[7]='0'+(char)captured_elf_slot; ttl[8]=':'; ttl[9]=' ';
            const char* cmd = elf_processes[captured_elf_slot].cmdline;
            int ci = 10;
            for (int k = 0; cmd[k] && ci < 42; k++, ci++) ttl[ci] = cmd[k];
            ttl[ci++] = ']'; ttl[ci] = 0;
            draw_string(ttl, x + 5, y + 8, TEXT_WHITE);
        } else {
            draw_string(title, x + 5, y + 8, TEXT_WHITE);
        }

        // Minimize button ("_"), sits just left of the close button.
        draw_rect_filled(x + w - 44, y + 4, 18, 18, BUTTON_FACE);
        draw_string("_", x + w - 39, y + 12, TEXT_BLACK);

        draw_rect_filled(x + w - 22, y + 4, 18, 18, BUTTON_CLOSE);
        draw_string("X", x + w - 17, y + 8, TEXT_WHITE);

        draw_rect_filled(x, y + 25, w, h - 25, WINDOW_BG);

        for (int i = 0; i < w; i++) put_pixel_back(x + i, y, WINDOW_BORDER);
        for (int i = 0; i < w; i++) put_pixel_back(x + i, y + h - 1, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x, y + i, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x + w - 1, y + i, WINDOW_BORDER);

        // ── Bochs self-test VGA overlay ─────────────────────────────────
        // When this terminal activated the `test` module, paint the three
        // VGA-style rows (breadcrumbs / fault tag / GUEST line) the module
        // wrote into g_test_vga[]. This reproduces test_main.cpp's 0xB8000
        // overlay inside the window. The terminal text is shifted down by
        // overlay_dy so it doesn't collide with the three rows.
        int overlay_dy = 0;
        if (!in_editor && g_test_overlay_active &&
            g_test_overlay_owner == (void*)this) {
            overlay_dy = render_test_overlay();
        }

        if (!in_editor) {
    // ── Guest graphics overlay ───────────────────────────────────────
    // If the running Bochs ELF has presented a framebuffer (see
    // bochs_drivers.h's gfx_present()), draw THAT instead of the text
    // buffer -- a program using graphics mode owns the whole content
    // area, the same way a real full-screen game would. Once the
    // guest calls gfx_exit() (or exits/is killed, via
    // bochs_release_slot's gfx_forget_slot), bochs_gfx_get_frame()
    // goes back to returning false and this window reverts to
    // ordinary text on the very next draw().
    const uint32_t* gfx_px = nullptr;
    int gfx_w = 0, gfx_h = 0;
    bool gfx_active = (captured_elf_slot >= 0) &&
        bochs_gfx_get_frame(captured_elf_slot, &gfx_px, &gfx_w, &gfx_h);

    if (gfx_active) {
        int content_top = y + 30 + overlay_dy;
        int avail_w = w - 10;
        int avail_h = (y + h) - content_top - 5;
        if (avail_w < 0) avail_w = 0;
        if (avail_h < 0) avail_h = 0;

        // Centre the guest's canvas inside whatever room is left; clip
        // rather than scale, so guests always get true 1:1 pixels.
        int draw_w = gfx_w < avail_w ? gfx_w : avail_w;
        int draw_h = gfx_h < avail_h ? gfx_h : avail_h;
        int off_x  = x + 5 + (avail_w - draw_w) / 2;
        int off_y  = content_top + (avail_h - draw_h) / 2;

        for (int row = 0; row < draw_h; row++) {
            const uint32_t* src_row = gfx_px + row * gfx_w;
            int py = off_y + row;
            for (int col = 0; col < draw_w; col++) {
                put_pixel_back(off_x + col, py, src_row[col]);
            }
        }

        // Publish this frame's canvas rect for the mouse ABI (see
        // gfx_hit_test() above) — kernel_gfx_mouse_poll() reads these
        // every time a guest polls, so they must stay in lockstep with
        // where the canvas was actually just blitted on screen.
        gfx_rect_x = off_x;
        gfx_rect_y = off_y;
        gfx_rect_w = draw_w;
        gfx_rect_h = draw_h;
        gfx_rect_valid = (draw_w > 0 && draw_h > 0);
    } else {
        gfx_rect_valid = false;
    // How many 10px text lines actually fit between the content-area
    // top (y + 30 + overlay_dy) and the window's bottom border (y + h).
    // The old code hard-coded `i < 38`, which — combined with the test
    // overlay shifting text down by overlay_dy — drew lines past the
    // bottom border ("overhanging by one"). Compute the real capacity.
    int content_top = 30 + overlay_dy;
    int visible_rows = (h - content_top) / 10;
    if (visible_rows < 1) visible_rows = 1;

    // When the buffer holds more lines than fit, show the most recent
    // ones (tail) rather than the oldest (head) — otherwise fresh guest
    // output scrolls off the bottom and stale text stays pinned at top.
    int first = line_count - visible_rows;
    if (first < 0) first = 0;

    for (int i = first; i < line_count; i++) {
        int screen_row = i - first;
        draw_string(buffer[i], x + 5, y + content_top + screen_row * 10,
                    ColorPalette::TEXT_WHITE);
    }
    }
} else {
    gfx_rect_valid = false;  // editor mode never shows a guest gfx canvas
    for (int row = 0; row < EDIT_ROWS; ++row) {
        int line_idx = edit_scroll_offset + row;
        int y_line = y + 30 + row * EDIT_LINE_PIX;

        if (line_idx < edit_line_count) {
            if (line_idx == edit_current_line) {
                draw_rect_filled(x + 2, y_line, w - 4, EDIT_LINE_PIX, ColorPalette::TEXT_GRAY);
            }
            draw_string(edit_lines[line_idx], x + 5, y_line, ColorPalette::TEXT_WHITE);
        }
    }

    if ((g_timer_ticks / 15) % 2 == 0 && edit_current_line >= edit_scroll_offset &&
        edit_current_line < edit_scroll_offset + EDIT_ROWS) {
        int visible_row = edit_current_line - edit_scroll_offset;
        int cursor_x = x + 5 + edit_cursor_col * EDIT_COL_PIX;
        int cursor_y = y + 30 + visible_row * EDIT_LINE_PIX;
        draw_rect_filled(cursor_x, cursor_y, EDIT_COL_PIX, EDIT_LINE_PIX, ColorPalette::CURSOR_WHITE);
    }
}
    }

    void on_key_press(char c) override {
    if (in_editor) {
        if (!edit_lines || edit_current_line >= edit_line_count) return;

        char* current_line_ptr = edit_lines[edit_current_line];
        size_t current_len = strlen(current_line_ptr);

        if (c == 17 || c == 27) { // Ctrl+Q or ESC to save and exit
            int total_len = 0;
            for (int i = 0; i < edit_line_count; i++) {
                total_len += strlen(edit_lines[i]) + 1;
            }
            char* file_content = new char[total_len + 1];
            if (!file_content) return;
            file_content[0] = '\0';
            for (int i = 0; i < edit_line_count; i++) {
                strcat(file_content, edit_lines[i]);
                if (i < edit_line_count - 1) {
                   strcat(file_content, "\n");
                }
            }
            fat32_write_file_path(edit_filename, file_content, strlen(file_content));
            delete[] file_content;
            in_editor = false;
            console_print("File saved.\n");
            return;
        } 
        else if (c == KEY_UP) {
            if (edit_current_line > 0) edit_current_line--;
        } 
        else if (c == KEY_DOWN) {
            if (edit_current_line < edit_line_count - 1) edit_current_line++;
        } 
        else if (c == KEY_LEFT) {
            if (edit_cursor_col > 0) edit_cursor_col--;
        } 
        else if (c == KEY_RIGHT) {
            if (edit_cursor_col < (int)current_len) edit_cursor_col++;
        } 
        else if (c == KEY_HOME) {
            edit_cursor_col = 0;
        }
        else if (c == KEY_END) {
            edit_cursor_col = current_len;
        }
        else if (c == KEY_DELETE) {
            if (edit_cursor_col < (int)current_len) {
                memmove(&current_line_ptr[edit_cursor_col], 
                       &current_line_ptr[edit_cursor_col + 1], 
                       current_len - edit_cursor_col);
            } else if (edit_current_line < edit_line_count - 1) {
                // Delete at end of line - join with next line
                char* next_line_ptr = edit_lines[edit_current_line + 1];
                if (current_len + strlen(next_line_ptr) < TERM_WIDTH - 1) {
                    strcat(current_line_ptr, next_line_ptr);
                    editor_delete_line_at(edit_current_line + 1);
                }
            }
        }
        else if (c == '\n') { // Enter key
            const char* right_part_text = &current_line_ptr[edit_cursor_col];
            editor_insert_line_at(edit_current_line + 1, right_part_text);
            current_line_ptr[edit_cursor_col] = '\0';
            edit_current_line++;
            edit_cursor_col = 0;
        } 
        else if (c == '\b') { // Backspace
            if (edit_cursor_col > 0) {
                memmove(&current_line_ptr[edit_cursor_col - 1], 
                       &current_line_ptr[edit_cursor_col], 
                       current_len - edit_cursor_col + 1);
                edit_cursor_col--;
            } else if (edit_current_line > 0) {
                int prev_line_idx = edit_current_line - 1;
                char* prev_line_ptr = edit_lines[prev_line_idx];
                int prev_len = strlen(prev_line_ptr);
                if (prev_len + current_len < TERM_WIDTH - 1) {
                    strcat(prev_line_ptr, current_line_ptr);
                    editor_delete_line_at(edit_current_line);
                    edit_current_line = prev_line_idx;
                    edit_cursor_col = prev_len;
                }
            }
        } 
        else if (c >= 32 && c < 127) { // Printable characters
            // **WORD WRAP IMPLEMENTATION**
            const int MAX_LINE_WIDTH = EDITOR_WRAP_WIDTH; // Characters before wrap
            
            if (current_len < TERM_WIDTH - 2) {
                // Insert character
                memmove(&current_line_ptr[edit_cursor_col + 1], 
                       &current_line_ptr[edit_cursor_col], 
                       current_len - edit_cursor_col + 1);
                current_line_ptr[edit_cursor_col] = c;
                edit_cursor_col++;
                
                // Check if line is too long and needs wrapping
                int new_len = strlen(current_line_ptr);
                if (new_len > MAX_LINE_WIDTH) {
                    // Find last space to wrap at
                    int wrap_pos = MAX_LINE_WIDTH;
                    bool found_space = false;
                    
                    for (int i = MAX_LINE_WIDTH; i > MAX_LINE_WIDTH - 20 && i > 0; i--) {
                        if (current_line_ptr[i] == ' ') {
                            wrap_pos = i;
                            found_space = true;
                            break;
                        }
                    }
                    
                    // If no space found near margin, force wrap at max width
                    if (!found_space) {
                        wrap_pos = MAX_LINE_WIDTH;
                    }
                    
                    // Create wrapped text for next line
                    char wrapped_text[TERM_WIDTH];
                    memset(wrapped_text, 0, TERM_WIDTH);
                    strcpy(wrapped_text, &current_line_ptr[wrap_pos]);
                    
                    // Trim leading space(s) from wrapped text
                    char* trimmed = wrapped_text;
                    while (*trimmed == ' ') trimmed++;
                    int trimmed_count = (int)(trimmed - wrapped_text);
                    
                    // Truncate current line at wrap point
                    current_line_ptr[wrap_pos] = '\0';
                    
                    // Insert wrapped text as new line
                    editor_insert_line_at(edit_current_line + 1, trimmed);
                    
                    // Move cursor to next line if it was past wrap point
                    if (edit_cursor_col > wrap_pos) {
                        edit_current_line++;
                        // New column = old column, minus the chars that
                        // stayed on line 1 (wrap_pos), minus the leading
                        // space(s) trimmed off line 2. Previously this was
                        // a loop re-testing the same fixed byte
                        // (wrapped_text[0], which the loop never updated),
                        // so it ran all the way down to column 0 any time
                        // the wrap point landed on a space — i.e. on every
                        // normal word wrap — yanking the cursor to the
                        // start of the new line while still mid-word.
                        edit_cursor_col = edit_cursor_col - wrap_pos - trimmed_count;
                        if (edit_cursor_col < 0) edit_cursor_col = 0;
                    }
                }
            }
        }
        
        editor_clamp_cursor_to_line();
        editor_ensure_cursor_visible();
        return; // END OF EDITOR HANDLING
    }	else {
		
		    // BUSYBOX CAPTURE
			if (captured_elf_slot >= 0) {
			// Echo + feed
			// Only echo printable bytes + newline/tab. Echoing arbitrary
			// key codes (modifier-key scancodes, arrow keys, etc.) drops
			// bytes 0-31 / 127 into the terminal buffer where they render
			// as blank spaces in font.h — the same mechanism that produced
			// the "HELL O" rendering bug. The raw byte still goes to the
			// ELF's stdin via push_input below, so applications that want
			// to interpret special keys still see them.
			unsigned char uc = (unsigned char)c;
			if (uc == '\n' || uc == '\t' || (uc >= 32 && uc < 127)) {
				char echo[2] = {c, 0};
				console_print(echo);
			}
			push_input(captured_elf_slot, c);
			if (c == '\n') elf_processes[captured_elf_slot].waiting_for_input = false;
			return;
		}
            if (c == '\n') {
                // run_contexts[] is indexed by its own slot, NOT by window index.
                // There is no 1:1 mapping between windows and run slots, so we
                // just always treat Enter as a command submission.
                prompt_visual_lines = 0;
                handle_command();
                line_pos = 0;
                current_line[0] = '\0';
                update_prompt_display();
            }
			
			else if (c == '\b') {
                if (line_pos > 0) {
                    line_pos--;
                    current_line[line_pos] = 0;
                }
                update_prompt_display();
            } else if (c >= 32 && c < 127 && line_pos < TERM_WIDTH - 2) {
                current_line[line_pos++] = c;
                current_line[line_pos] = 0;
                update_prompt_display();
            }
        }
    }

     // --- THIS IS THE CORRECTED UPDATE METHOD ---
    void update() override {
        // Check if there is a startup command waiting to be executed
        if (private_startup_cmd[0] != '\0') {
            strncpy(current_line, private_startup_cmd, TERM_WIDTH - 1);
            current_line[TERM_WIDTH - 1] = '\0';
            private_startup_cmd[0] = '\0';
            push_line(current_line);
            handle_command();
            line_pos = 0;
            current_line[0] = '\0';
            update_prompt_display();
        }
    }


    void console_print(const char* s) override {
        if (!s || in_editor) return;

        // ── Sanitize input ────────────────────────────────────────────────
        // Filter to printable ASCII plus the whitespace we explicitly handle
        // (\n, \t). Without this, any byte 0-31 or 127 in `s` (uninitialized
        // stack memory, echoed modifier keys, stray emulator garbage, etc.)
        // gets stuffed verbatim into the terminal buffer. Those bytes have
        // empty glyphs in font.h, so they RENDER AS BLANK SPACES — visually
        // identical to U+0020. This is the root cause of bugs like
        // "HELLO" displaying as "HELL O": a stray control byte landed in
        // the buffer between L and O. \r is converted to \n for safety;
        // \b is intentionally NOT supported here (the legitimate guest
        // output paths don't emit it, and accepting it would let stray
        // 0x08 bytes erase real output).
        char clean[8192];
        int  cn = 0;
        for (const char* p = s; *p && cn < (int)sizeof(clean) - 1; ++p) {
            unsigned char c = (unsigned char)*p;
            if (c == '\n' || c == '\t')             clean[cn++] = (char)c;
            else if (c == '\r')                     clean[cn++] = '\n';
            else if (c >= 32 && c < 127)            clean[cn++] = (char)c;
            // else: drop (would render blank and corrupt the display).
        }
        clean[cn] = '\0';
        if (cn == 0) return;

        int saved_prompt_lines = prompt_visual_lines;
        if (saved_prompt_lines > 0) {
            remove_last_n_lines(saved_prompt_lines);
            prompt_visual_lines = 0;
        }

        push_wrapped_text(clean, term_cols_cont());
        update_prompt_display();
    }
};
