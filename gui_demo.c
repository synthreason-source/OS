/* compositor.h — a tiny GUI toolkit for guest ELF gfx programs.
 *
 * Not to be confused with the kernel's own compositor (the window
 * manager in kernel_parts/04_window_system.h / 10_window_manager_impl.h)
 * — that one owns the desktop, windows, titlebars, and the one shared
 * mouse cursor, and always keeps first claim on clicks (dragging a
 * window, closing it, clicking another window, the desktop, the
 * taskbar). THIS header is the layer built on top of what the kernel
 * compositor hands a focused gfx-mode program through bochs_drivers.h's
 * mouse_poll()/key_poll(): turning that raw per-frame cursor+keyboard
 * snapshot into buttons, a scrollbar, and a text box a guest program
 * can just drop into its own draw loop.
 *
 *     #include "bochs_drivers.h"
 *     #include "compositor.h"
 *
 *     ui_button_t   quit_btn = { 10, 10, 60, 20, "Quit" };
 *     ui_scrollbar_t bar;    ui_scrollbar_init(&bar, 300, 10, 12, 180, 0, 100, 0);
 *     ui_textbox_t   box;     ui_textbox_init(&box, 10, 40, 200, 18);
 *
 *     void _start(void) {
 *         for (;;) {
 *             ui_frame_t f;
 *             ui_frame_begin(&f, 0x202028);      // polls mouse+key, clears canvas
 *
 *             if (ui_button(&f, &quit_btn))  break;
 *             ui_scrollbar_update(&f, &bar);
 *             ui_scrollbar_draw(&bar);
 *             ui_textbox_update(&f, &box);
 *             ui_textbox_draw(&box);
 *
 *             ui_frame_end();                     // gfx_present()
 *         }
 *         gfx_exit();
 *         kexit(0);
 *     }
 *
 * No libc, no dynamic memory — every widget's state lives in a plain
 * struct the caller owns (usually as a file-scope static), the same
 * "no hidden state" style as the rest of the guest ABI in
 * bochs_drivers.h. Everything draws into bochs_drivers.h's own
 * gfx_framebuffer (320x200, 0xRRGGBB) via gfx_set_pixel(); there's no
 * separate buffer to manage.
 */
#pragma once

#include "bochs_drivers.h"
#include "font.h"

/* ── palette ─────────────────────────────────────────────────────── */

#define UI_COLOR_BG          0x202028
#define UI_COLOR_PANEL       0x30303A
#define UI_COLOR_BORDER      0x55555F
#define UI_COLOR_TEXT        0xE8E8E8
#define UI_COLOR_TEXT_DIM    0x8A8A96
#define UI_COLOR_BUTTON      0x3E3E4A
#define UI_COLOR_BUTTON_HOT  0x4E4E60
#define UI_COLOR_BUTTON_DOWN 0x5C7CFA
#define UI_COLOR_ACCENT      0x5C7CFA
#define UI_COLOR_CURSOR      0xFFFFFF

/* ── low-level drawing (into gfx_framebuffer) ───────────────────── */

static inline void ui_fill_rect(int x, int y, int w, int h, unsigned int color)
{
    for (int j = 0; j < h; j++)
        for (int i = 0; i < w; i++)
            gfx_set_pixel(x + i, y + j, color);
}

static inline void ui_stroke_rect(int x, int y, int w, int h, unsigned int color)
{
    for (int i = 0; i < w; i++) {
        gfx_set_pixel(x + i, y, color);
        gfx_set_pixel(x + i, y + h - 1, color);
    }
    for (int j = 0; j < h; j++) {
        gfx_set_pixel(x, y + j, color);
        gfx_set_pixel(x + w - 1, y + j, color);
    }
}

/* 8x8 bitmap glyph, 1:1 scale, from font.h */
static inline void ui_draw_char(int x, int y, char c, unsigned int color)
{
    unsigned char ch = (unsigned char)c;
    if (ch >= 128) return;

    const unsigned char* glyph = &font[ch * 8];
    for (int row = 0; row < 8; row++) {
        unsigned char bits = glyph[row];
        for (int col = 0; col < 8; col++) {
            if (bits & (0x80 >> col))
                gfx_set_pixel(x + col, y + row, color);
        }
    }
}

static inline void ui_draw_text(int x, int y, const char* s, unsigned int color)
{
    int cx = x;
    while (*s) {
        if (*s == '\n') {
            cx = x;
            y += 9;
            s++;
            continue;
        }
        ui_draw_char(cx, y, *s, color);
        cx += 8;
        s++;
    }
}

static inline int ui_text_width(const char* s)
{
    int w = 0;
    while (*s++) w += 8;
    return w;
}

/* ── frame: one mouse+keyboard snapshot for this pass of the loop ── */

typedef struct {
    mouse_state_t mouse;
    int key; /* key_poll() result: 0 = none, else the char/KEY_* code */
} ui_frame_t;

static inline void ui_frame_begin(ui_frame_t* f, unsigned int bg_color)
{
    mouse_poll(&f->mouse);
    f->key = key_poll();
    gfx_clear(bg_color);
}

static inline void ui_frame_end(void)
{
    gfx_present();
}

static inline int ui_point_in_rect(int px, int py, int x, int y, int w, int h)
{
    return px >= x && px < x + w && py >= y && py < y + h;
}

/* ── button ──────────────────────────────────────────────────────── */

typedef struct {
    int x, y, w, h;
    const char* label;
} ui_button_t;

static inline int ui_button(const ui_frame_t* f, const ui_button_t* b)
{
    int hot = f->mouse.in_window &&
              ui_point_in_rect(f->mouse.x, f->mouse.y, b->x, b->y, b->w, b->h);
    int clicked = hot && f->mouse.left_clicked;

    unsigned int face = UI_COLOR_BUTTON;
    if (hot)
        face = f->mouse.left_down ? UI_COLOR_BUTTON_DOWN : UI_COLOR_BUTTON_HOT;

    ui_fill_rect(b->x, b->y, b->w, b->h, face);
    ui_stroke_rect(b->x, b->y, b->w, b->h, UI_COLOR_BORDER);

    if (b->label) {
        int tw = ui_text_width(b->label);
        int tx = b->x + (b->w - tw) / 2;
        int ty = b->y + (b->h - 8) / 2;
        if (tx < b->x + 2) tx = b->x + 2;
        if (ty < b->y) ty = b->y;
        ui_draw_text(tx, ty, b->label, UI_COLOR_TEXT);
    }

    return clicked;
}

/* ── scrollbar (vertical) ───────────────────────────────────────── */

typedef struct {
    int x, y, w, h;
    int min, max;
    int value;
    int dragging;
    int drag_grab_offset;
} ui_scrollbar_t;

static inline void ui_scrollbar_init(ui_scrollbar_t* s, int x, int y, int w, int h,
                                     int min, int max, int initial)
{
    s->x = x;
    s->y = y;
    s->w = w;
    s->h = h;
    s->min = min;
    s->max = max;
    s->value = initial < min ? min : (initial > max ? max : initial);
    s->dragging = 0;
    s->drag_grab_offset = 0;
}

static inline int ui__scrollbar_thumb_h(const ui_scrollbar_t* s)
{
    int th = s->h / 4;
    return th < 12 ? 12 : th;
}

static inline int ui__scrollbar_thumb_y(const ui_scrollbar_t* s)
{
    int range = s->max - s->min;
    int th = ui__scrollbar_thumb_h(s);
    int track = s->h - th;
    if (track < 0) track = 0;
    if (range <= 0) return s->y;
    return s->y + (s->value - s->min) * track / range;
}

static inline void ui_scrollbar_update(const ui_frame_t* f, ui_scrollbar_t* s)
{
    int thumb_h = ui__scrollbar_thumb_h(s);
    int thumb_y = ui__scrollbar_thumb_y(s);

    if (s->dragging) {
        if (!f->mouse.left_down) {
            s->dragging = 0;
        } else if (f->mouse.in_window) {
            int track = s->h - thumb_h;
            int range = s->max - s->min;
            int new_thumb_y = f->mouse.y - s->drag_grab_offset;
            int rel = new_thumb_y - s->y;
            if (rel < 0) rel = 0;
            if (rel > track) rel = track;

            if (track > 0 && range > 0)
                s->value = s->min + (rel * range) / track;
            else
                s->value = s->min;
        }
        return;
    }

    if (!f->mouse.in_window || !f->mouse.left_clicked) return;
    if (!ui_point_in_rect(f->mouse.x, f->mouse.y, s->x, s->y, s->w, s->h)) return;

    if (ui_point_in_rect(f->mouse.x, f->mouse.y, s->x, thumb_y, s->w, thumb_h)) {
        s->dragging = 1;
        s->drag_grab_offset = f->mouse.y - thumb_y;
    } else {
        int range = s->max - s->min;
        int page = range > 4 ? range / 4 : 1;
        if (f->mouse.y < thumb_y)
            s->value -= page;
        else
            s->value += page;
        if (s->value < s->min) s->value = s->min;
        if (s->value > s->max) s->value = s->max;
    }
}

static inline void ui_scrollbar_draw(const ui_scrollbar_t* s)
{
    ui_fill_rect(s->x, s->y, s->w, s->h, UI_COLOR_PANEL);
    ui_stroke_rect(s->x, s->y, s->w, s->h, UI_COLOR_BORDER);

    int thumb_h = ui__scrollbar_thumb_h(s);
    int thumb_y = ui__scrollbar_thumb_y(s);
    ui_fill_rect(s->x + 1, thumb_y, s->w - 2, thumb_h,
                 s->dragging ? UI_COLOR_BUTTON_DOWN : UI_COLOR_ACCENT);
}

/* ── text box (single line) ─────────────────────────────────────── */

#define UI_TEXTBOX_MAX 64

typedef struct {
    int x, y, w, h;
    char buf[UI_TEXTBOX_MAX];
    int len;
    int focused;
} ui_textbox_t;

static inline void ui_textbox_init(ui_textbox_t* t, int x, int y, int w, int h)
{
    t->x = x;
    t->y = y;
    t->w = w;
    t->h = h;
    t->buf[0] = 0;
    t->len = 0;
    t->focused = 0;
}

static inline void ui_textbox_update(const ui_frame_t* f, ui_textbox_t* t)
{
    if (f->mouse.in_window && f->mouse.left_clicked)
        t->focused = ui_point_in_rect(f->mouse.x, f->mouse.y, t->x, t->y, t->w, t->h);

    if (!t->focused || f->key == 0) return;

    int k = f->key;
    if (k == '\b' || k == 127 || k == KEY_DELETE) {
        if (t->len > 0) {
            t->len--;
            t->buf[t->len] = '\0';
        }
    } else if (k == '\n' || k == '\r') {
        t->focused = 0;
    } else if ((k >= 32 && k <= 126) && (t->len < UI_TEXTBOX_MAX - 1)) {
        t->buf[t->len++] = (char)k;
        t->buf[t->len] = '\0';
    }
}

static inline void ui_textbox_draw(const ui_textbox_t* t)
{
    ui_fill_rect(t->x, t->y, t->w, t->h, UI_COLOR_PANEL);
    ui_stroke_rect(t->x, t->y, t->w, t->h, t->focused ? UI_COLOR_ACCENT : UI_COLOR_BORDER);
    ui_draw_text(t->x + 4, t->y + (t->h - 8) / 2, t->buf, UI_COLOR_TEXT);

    if (t->focused) {
        int caret_x = t->x + 4 + ui_text_width(t->buf);
        int caret_max = t->x + t->w - 2;
        if (caret_x > caret_max) caret_x = caret_max;
        int cy = t->y + (t->h - 8) / 2;
        for (int i = 0; i < 8; i++)
            gfx_set_pixel(caret_x, cy + i, UI_COLOR_ACCENT);
    }
}

/* ── cursor ─────────────────────────────────────────────────────── */

static inline void ui_draw_debug_cursor(const ui_frame_t* f)
{
    if (!f->mouse.in_window) return;
    int x = f->mouse.x, y = f->mouse.y;
    for (int i = 0; i < 6; i++) gfx_set_pixel(x, y + i, UI_COLOR_CURSOR);
    for (int i = 0; i < 6; i++) gfx_set_pixel(x + i, y, UI_COLOR_CURSOR);
}
