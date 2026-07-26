/* text_edit.c — a small but fully-featured multi-line text editor
 * built on top of comp.h's widgets and drivers.h's FAT32 disk ABI.
 *
 * Build (from the host):
 *     make cc SRC=text_edit.c
 * Or from the OS shell:
 *     cc text_edit.c
 *     text_edit
 *
 * Features
 * --------
 *   - Multi-line editing: type to insert, Backspace/Delete to remove,
 *     Enter for a new line.
 *   - Full cursor navigation: arrow keys, Home/End, and click-to-place
 *     anywhere in the visible text.
 *   - Both vertical AND horizontal scrolling, so lines and files
 *     longer than the visible area just work — the view follows the
 *     cursor automatically.
 *   - "Sticky" column when moving Up/Down (like every other editor:
 *     moving through a short line and back to a long one returns you
 *     to the column you started at, not column 0).
 *   - New / Open / Save toolbar buttons, driven by a filename field
 *     (reusing comp.h's ui_textbox_t — its 64-byte capacity lines up
 *     exactly with disk_mailbox_t's name[64], so no truncation
 *     surprises).
 *   - A live status line: line/col, byte count vs. capacity, a
 *     "*modified*" flag, and the result of the last New/Open/Save.
 *   - A lightweight "Quit" confirmation: if there are unsaved changes,
 *     the button relabels itself to "Confirm Quit" and only exits on
 *     the *second* click — any further edit or action re-arms it back
 *     to a plain "Quit". No modal dialog widget exists in this ABI,
 *     so this two-click pattern is the safety net instead.
 *   - A fully live-resizable canvas: the text area, its visible
 *     line/column count, and the toolbar all recompute themselves
 *     every frame from GFX_WIDTH/GFX_HEIGHT (bochs_drivers.h), which
 *     comp.h's ui_frame_begin() refreshes each frame from this
 *     program's own terminal window. Drag the window bigger or
 *     smaller mid-session and the editor just fills whatever room
 *     it's given, no restart needed.
 *
 * Design notes (why it looks the way it does)
 * --------------------------------------------
 *   - No libc, no malloc: the whole document lives in one static,
 *     fixed-size char array (EDITOR_MAX bytes), edited in place with
 *     memmove-style shifts. That's plenty for a guest text file and
 *     matches the "no hidden state" style the rest of this ABI uses.
 *   - key_poll() hands back at most one key per frame and is polled
 *     unconditionally (never getch()), so the GUI loop never blocks
 *     and mouse_poll()/gfx_present() keep running every frame even
 *     while the user is mid-keystroke.
 *   - Only one widget can be "focused" at a time: clicking inside the
 *     text area focuses the editor and defocuses the filename box (or
 *     vice versa), the same rectangle-test convention ui_textbox_t
 *     already uses internally, just extended to a second widget.
 *   - Lines are tracked implicitly as '\n'-delimited runs inside the
 *     flat buffer — there's no separate line-index table to keep in
 *     sync, just a handful of scan helpers (line_start_of,
 *     line_end_of, line_number_of, pos_of_line_col). Simple, and the
 *     buffer is small enough that scanning it once a frame is free.
 */
#include "comp.h"

/* ── document buffer ─────────────────────────────────────────────── */
#define EDITOR_MAX 8192

static char s_text[EDITOR_MAX];
static int  s_text_len = 0;
static int  s_cursor   = 0;   /* index into s_text, 0..s_text_len     */
static int  s_pref_col = 0;   /* "sticky" column for Up/Down           */

static int  s_scroll_line = 0;
static int  s_scroll_col  = 0;
static int  s_modified    = 0;
static int  s_editor_focused = 1;
static int  s_quit_armed  = 0;

static char s_message[48] = "Ready.";
static char s_status[96];

static ui_textbox_t s_filename;

/* ── text-area geometry ───────────────────────────────────────────────
 * GFX_WIDTH/GFX_HEIGHT (bochs_drivers.h) now track this program's own
 * terminal window LIVE — comp.h's ui_frame_begin() refreshes them
 * every frame — so the layout below is recomputed once per frame
 * (editor_layout(), called at the top of the main loop) rather than
 * fixed at compile time. EDIT_X/EDIT_Y (top-left corner, below the
 * toolbar) stay constant; everything sized off the window's current
 * width/height does not. */
#define EDIT_X 4
#define EDIT_Y 52
#define CHAR_W 8
#define LINE_H 10

static int s_edit_w    = 200;   /* recomputed each frame by editor_layout() */
static int s_edit_h    = 100;
static int s_vis_cols  = 20;
static int s_vis_lines = 8;

static void editor_layout(void)
{
    s_edit_w = GFX_WIDTH - 2 * EDIT_X;
    if (s_edit_w < 40) s_edit_w = 40;

    s_edit_h = GFX_HEIGHT - EDIT_Y - 16;   /* room left for the status line below */
    if (s_edit_h < 20) s_edit_h = 20;

    s_vis_cols = (s_edit_w - 8) / CHAR_W;
    if (s_vis_cols < 1) s_vis_cols = 1;

    s_vis_lines = (s_edit_h - 4) / LINE_H;
    if (s_vis_lines < 1) s_vis_lines = 1;
}
void* memset(void* d, int v, unsigned long n) {
    unsigned char* dd=(unsigned char*)d;
    for (unsigned long i=0;i<n;i++) dd[i]=(unsigned char)v;
    return d;
}

/* ── tiny string helpers (no libc available, see drivers.h) ─────── */
static unsigned int strlen_local(const char *s) { unsigned int n = 0; while (s[n]) n++; return n; }

static int append_str(char *dst, int pos, const char *s)
{
    while (*s) dst[pos++] = *s++;
    dst[pos] = 0;
    return pos;
}

static int append_int(char *dst, int pos, int v)
{
    if (v == 0) { dst[pos++] = '0'; dst[pos] = 0; return pos; }
    unsigned int u = (v < 0) ? (unsigned int)(-v) : (unsigned int)v;
    if (v < 0) dst[pos++] = '-';
    char tmp[12]; int n = 0;
    while (u && n < 12) { tmp[n++] = (char)('0' + (u % 10)); u /= 10; }
    while (n) dst[pos++] = tmp[--n];
    dst[pos] = 0;
    return pos;
}

static void strcpy_local(char *dst, const char *src) { int p = 0; while (src[p]) { dst[p] = src[p]; p++; } dst[p] = 0; }

/* ── line/column helpers over the flat s_text buffer ────────────── */
static int line_start_of(int pos)
{
    while (pos > 0 && s_text[pos - 1] != '\n') pos--;
    return pos;
}

static int line_end_of(int pos)
{
    while (pos < s_text_len && s_text[pos] != '\n') pos++;
    return pos;
}

static int line_number_of(int pos)
{
    int line = 0;
    for (int i = 0; i < pos && i < s_text_len; i++) if (s_text[i] == '\n') line++;
    return line;
}

static int pos_of_line_col(int target_line, int col)
{
    int pos = 0, line = 0;
    while (line < target_line && pos < s_text_len) {
        if (s_text[pos] == '\n') line++;
        pos++;
    }
    int ls = pos;
    int le = line_end_of(ls);
    int p  = ls + col;
    if (p > le) p = le;
    if (p < ls) p = ls;
    return p;
}

/* ── editing primitives ──────────────────────────────────────────── */
static void editor_insert_char(char c)
{
    if (s_text_len >= EDITOR_MAX - 1) { strcpy_local(s_message, "Buffer full!"); return; }
    for (int i = s_text_len; i > s_cursor; i--) s_text[i] = s_text[i - 1];
    s_text[s_cursor] = c;
    s_text_len++;
    s_cursor++;
    s_pref_col = s_cursor - line_start_of(s_cursor);
    s_modified = 1;
}

static void editor_backspace(void)
{
    if (s_cursor <= 0) return;
    for (int i = s_cursor - 1; i < s_text_len - 1; i++) s_text[i] = s_text[i + 1];
    s_text_len--;
    s_cursor--;
    s_pref_col = s_cursor - line_start_of(s_cursor);
    s_modified = 1;
}

static void editor_delete_forward(void)
{
    if (s_cursor >= s_text_len) return;
    for (int i = s_cursor; i < s_text_len - 1; i++) s_text[i] = s_text[i + 1];
    s_text_len--;
    s_modified = 1;
}

/* ── cursor movement ─────────────────────────────────────────────── */
static void editor_move_left(void)
{
    if (s_cursor > 0) s_cursor--;
    s_pref_col = s_cursor - line_start_of(s_cursor);
}
static void editor_move_right(void)
{
    if (s_cursor < s_text_len) s_cursor++;
    s_pref_col = s_cursor - line_start_of(s_cursor);
}
static void editor_move_up(void)
{
    int cur_line = line_number_of(s_cursor);
    if (cur_line == 0) return;
    s_cursor = pos_of_line_col(cur_line - 1, s_pref_col);
}
static void editor_move_down(void)
{
    int cur_line = line_number_of(s_cursor);
    s_cursor = pos_of_line_col(cur_line + 1, s_pref_col);
}
static void editor_home(void) { s_cursor = line_start_of(s_cursor); s_pref_col = 0; }
static void editor_end(void)
{
    s_cursor = line_end_of(s_cursor);
    s_pref_col = s_cursor - line_start_of(s_cursor);
}

static void editor_click_to_cursor(int mx, int my)
{
    int col  = (mx - (EDIT_X + 4)) / CHAR_W + s_scroll_col;
    int line = (my - (EDIT_Y + 2)) / LINE_H + s_scroll_line;
    if (col  < 0) col  = 0;
    if (line < 0) line = 0;
    s_cursor   = pos_of_line_col(line, col);
    s_pref_col = s_cursor - line_start_of(s_cursor);
}

static void editor_adjust_scroll(void)
{
    int cl  = line_number_of(s_cursor);
    int col = s_cursor - line_start_of(s_cursor);

    if (cl < s_scroll_line) s_scroll_line = cl;
    if (cl >= s_scroll_line + s_vis_lines) s_scroll_line = cl - s_vis_lines + 1;
    if (col < s_scroll_col) s_scroll_col = col;
    if (col >= s_scroll_col + s_vis_cols) s_scroll_col = col - s_vis_cols + 1;
    if (s_scroll_line < 0) s_scroll_line = 0;
    if (s_scroll_col  < 0) s_scroll_col  = 0;
}

/* ── file operations ──────────────────────────────────────────────── */
static void editor_new(void)
{
    s_text_len = 0; s_cursor = 0; s_pref_col = 0;
    s_scroll_line = 0; s_scroll_col = 0;
    s_modified = 0; s_quit_armed = 0;
    strcpy_local(s_message, "New file.");
}

static void editor_open(void)
{
    if (s_filename.len == 0) { strcpy_local(s_message, "Enter a filename first."); return; }

    unsigned int size = 0;
    int st = kfstat(s_filename.buf, &size);
    if (st != DISK_OK) { strcpy_local(s_message, "Open failed: not found."); return; }
    if (size >= (unsigned int)(EDITOR_MAX - 1)) { strcpy_local(s_message, "Open failed: file too large."); return; }

    int rd = kfread(s_filename.buf, s_text, EDITOR_MAX - 1);
    if (rd < 0) { strcpy_local(s_message, "Open failed: read error."); return; }

    s_text_len = rd; s_cursor = 0; s_pref_col = 0;
    s_scroll_line = 0; s_scroll_col = 0;
    s_modified = 0; s_quit_armed = 0;

    int p = 0;
    p = append_str(s_message, p, "Loaded ");
    p = append_int(s_message, p, rd);
    p = append_str(s_message, p, " bytes.");
}

static void editor_save(void)
{
    if (s_filename.len == 0) { strcpy_local(s_message, "Enter a filename first."); return; }

    int st = kfwrite(s_filename.buf, s_text, (unsigned int)s_text_len);
    if (st == DISK_OK) {
        s_modified = 0; s_quit_armed = 0;
        int p = 0;
        p = append_str(s_message, p, "Saved ");
        p = append_int(s_message, p, s_text_len);
        p = append_str(s_message, p, " bytes.");
    } else {
        strcpy_local(s_message, "Save failed.");
    }
}

/* ── drawing ──────────────────────────────────────────────────────── */
static void editor_draw(void)
{
    ui_fill_rect(EDIT_X, EDIT_Y, s_edit_w, s_edit_h, UI_COLOR_PANEL);
    ui_stroke_rect(EDIT_X, EDIT_Y, s_edit_w, s_edit_h, s_editor_focused ? UI_COLOR_ACCENT : UI_COLOR_BORDER);

    int line = 0, col = 0;

    for (int i = 0; i <= s_text_len; i++) {
        if (i == s_cursor && s_editor_focused &&
            line >= s_scroll_line && line < s_scroll_line + s_vis_lines &&
            col  >= s_scroll_col  && col  < s_scroll_col  + s_vis_cols) {
            int cx = EDIT_X + 4 + (col  - s_scroll_col)  * CHAR_W;
            int cy = EDIT_Y + 2 + (line - s_scroll_line) * LINE_H;
            for (int k = 0; k < 8; k++) gfx_set_pixel(cx, cy + k, UI_COLOR_CURSOR);
        }
        if (i == s_text_len) break;

        char c = s_text[i];
        if (c == '\n') { line++; col = 0; continue; }

        if (line >= s_scroll_line && line < s_scroll_line + s_vis_lines &&
            col  >= s_scroll_col  && col  < s_scroll_col  + s_vis_cols) {
            int cx = EDIT_X + 4 + (col  - s_scroll_col)  * CHAR_W;
            int cy = EDIT_Y + 2 + (line - s_scroll_line) * LINE_H;
            ui_draw_char(cx, cy, c, UI_COLOR_TEXT);
        }
        col++;
    }
}

static void build_status(void)
{
    int line = line_number_of(s_cursor) + 1;
    int col  = (s_cursor - line_start_of(s_cursor)) + 1;

    int p = 0;
    p = append_str(s_status, p, "Ln ");
    p = append_int(s_status, p, line);
    p = append_str(s_status, p, "  Col ");
    p = append_int(s_status, p, col);
    p = append_str(s_status, p, "   ");
    p = append_int(s_status, p, s_text_len);
    p = append_str(s_status, p, "/");
    p = append_int(s_status, p, EDITOR_MAX - 1);
    p = append_str(s_status, p, " chars");
    if (s_modified) p = append_str(s_status, p, "   *modified*");
}

void _start(void)
{
    kputs("text_edit: starting (New/Open/Save + full multi-line editing)...\n");

    ui_textbox_init(&s_filename, 40, 28, 220, 16);
    strcpy_local(s_filename.buf, "untitled.txt");
    s_filename.len = (int)strlen_local(s_filename.buf);

    ui_button_t new_btn  = { 4,   4, 50, 20, "New"  };
    ui_button_t open_btn = { 58,  4, 50, 20, "Open" };
    ui_button_t save_btn = { 112, 4, 50, 20, "Save" };

    for (;;) {
        ui_frame_t f;
        ui_frame_begin(&f, UI_COLOR_BG);   /* also refreshes GFX_WIDTH/GFX_HEIGHT */
        editor_layout();                   /* recompute the text area for this frame's size */

        if (ui_button(&f, &new_btn))  editor_new();
        if (ui_button(&f, &open_btn)) editor_open();
        if (ui_button(&f, &save_btn)) editor_save();

        ui_button_t quit_btn;
        quit_btn.x = GFX_WIDTH - 74;
        quit_btn.y = 4;
        quit_btn.w = 70;
        quit_btn.h = 20;
        quit_btn.label = s_quit_armed ? "Confirm Quit" : "Quit";
        int quit_clicked = ui_button(&f, &quit_btn);

        ui_draw_text(4, 30, "File:", UI_COLOR_TEXT_DIM);
        ui_textbox_update(&f, &s_filename);
        ui_textbox_draw(&s_filename);

        /* Message goes to the right of the filename box if there's
         * room, otherwise it drops to its own row instead — on a
         * narrow window a fixed x=270 could land off-canvas or
         * overlap the toolbar. */
        if (GFX_WIDTH >= 270 + 8 * 8) ui_draw_text(270, 30, s_message, UI_COLOR_TEXT_DIM);
        else                          ui_draw_text(4, 46, s_message, UI_COLOR_TEXT_DIM);

        /* Whichever widget's rect the click landed in gets focus this
         * frame; the other loses it — same convention ui_textbox_t
         * already uses internally, just extended to a second widget
         * so only one of them ever consumes this frame's key_poll(). */
        if (f.mouse.in_window && f.mouse.left_clicked) {
            s_editor_focused = ui_point_in_rect(f.mouse.x, f.mouse.y, EDIT_X, EDIT_Y, s_edit_w, s_edit_h);
            if (s_editor_focused) editor_click_to_cursor(f.mouse.x, f.mouse.y);
        }

        if (s_editor_focused && f.key != 0) {
            int k = f.key;
            s_quit_armed = 0;  /* any activity re-arms the quit confirmation */

            if      (k == KEY_LEFT)   editor_move_left();
            else if (k == KEY_RIGHT)  editor_move_right();
            else if (k == KEY_UP)     editor_move_up();
            else if (k == KEY_DOWN)   editor_move_down();
            else if (k == KEY_HOME)   editor_home();
            else if (k == KEY_END)    editor_end();
            else if (k == KEY_DELETE) editor_delete_forward();
            else if (k == '\b' || k == 127) editor_backspace();
            else if (k == '\n' || k == '\r') editor_insert_char('\n');
            else if (k == '\t') { for (int s = 0; s < 4; s++) editor_insert_char(' '); }
            else if (k >= 32 && k < 127) editor_insert_char((char)k);
        }

        editor_adjust_scroll();
        editor_draw();

        build_status();
        ui_draw_text(EDIT_X, EDIT_Y + s_edit_h + 6, s_status, UI_COLOR_TEXT_DIM);

        ui_frame_end();

        if (quit_clicked) {
            if (!s_modified || s_quit_armed) break;
            s_quit_armed = 1;
            strcpy_local(s_message, "Unsaved changes! Click Quit again to discard.");
        }
    }

    gfx_exit();
    kputs("text_edit: exiting.\n");
    kexit(0);
}