// =====================================================================
// desktop_suite/base_window.h — shared chrome helper for all apps
// =====================================================================
//
// Subclass BaseAppWindow instead of Window directly. You get for free:
//   • 25-px titlebar with the same look as kernel.cpp's TerminalWindow
//   • 18×18 red close button (clickable, routes to close())
//   • 1-px window border
//   • a clean content rect (cx, cy, cw, ch) handed to draw_content()
//   • framework for input: override on_key(c) and on_click(rel_x, rel_y)
//
// Place this header in the same directory as kernel.cpp and include it
// from each app header. Depends on kernel.cpp providing:
//   Window base class, draw_rect_filled, draw_string, put_pixel_back,
//   ColorPalette::* constants.

#ifndef DESKTOP_BASE_WINDOW_H
#define DESKTOP_BASE_WINDOW_H

// Forward-decl drawing primitives — kernel.cpp defines them.
void draw_rect_filled(int x, int y, int w, int h, uint32_t color);
void put_pixel_back(int x, int y, uint32_t color);
void draw_string(const char* str, int x, int y, uint32_t color);
void draw_char(char c, int x, int y, uint32_t color);

// Title bar height — matches the kernel-wide convention.
static constexpr int APP_TITLEBAR_H = 25;
// 18×18 close-button rect, top-right of titlebar.
static constexpr int APP_CLOSEBTN_W = 18;

class BaseAppWindow : public Window {
public:
    BaseAppWindow(int x, int y, int w, int h, const char* title)
        : Window(x, y, w, h, title) {}

    // Final-ish draw — apps should override draw_content() instead.
    void draw() override {
        using namespace ColorPalette;
        uint32_t tb = has_focus ? TITLEBAR_ACTIVE : TITLEBAR_INACTIVE;

        // Titlebar + title + close
        draw_rect_filled(x, y, w, APP_TITLEBAR_H, tb);
        draw_string(title ? title : "Window", x + 6, y + 8, TEXT_WHITE);
        draw_rect_filled(x + w - 22, y + 4, APP_CLOSEBTN_W, APP_CLOSEBTN_W, BUTTON_CLOSE);
        draw_string("X", x + w - 17, y + 8, TEXT_WHITE);

        // Body fill — apps will repaint over this as needed
        draw_rect_filled(x, y + APP_TITLEBAR_H, w, h - APP_TITLEBAR_H, bg_color());

        // 1-px border
        for (int i = 0; i < w; i++) put_pixel_back(x + i, y, WINDOW_BORDER);
        for (int i = 0; i < w; i++) put_pixel_back(x + i, y + h - 1, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x, y + i, WINDOW_BORDER);
        for (int i = 0; i < h; i++) put_pixel_back(x + w - 1, y + i, WINDOW_BORDER);

        // Hand content rect to subclass
        draw_content(x, y + APP_TITLEBAR_H, w, h - APP_TITLEBAR_H);
    }

    // Apps that just need a per-frame tick (clocks, games) can override
    // this. update() also calls draw() implicitly via the kernel's
    // render loop, so a no-op update() is fine for static apps.
    void update() override {}

    // Click router — converts absolute coords to content-rel coords.
    void on_mouse_click(int mx, int my) override {
        // Close button
        if (mx >= x + w - 22 && mx < x + w - 4 && my >= y + 4 && my < y + 22) {
            close();
            return;
        }
        // Body
        if (my > y + APP_TITLEBAR_H && mx > x && mx < x + w && my < y + h) {
            on_click(mx - x, my - (y + APP_TITLEBAR_H));
        }
    }

    // Subclasses override these:
    virtual void draw_content(int cx, int cy, int cw, int ch) { (void)cx; (void)cy; (void)cw; (void)ch; }
    virtual void on_click(int rel_x, int rel_y) { (void)rel_x; (void)rel_y; }
    void on_key_press(char c) override { (void)c; }

    // Default body color — override per app if you want.
    virtual uint32_t bg_color() const { return ColorPalette::BUTTON_FACE; }
};

// ---------------------------------------------------------------------
// Tiny shared helpers used by several apps
// ---------------------------------------------------------------------

// Right-aligned int-to-string, 0-padded to width. Writes into out_buf
// (must hold width+1 bytes).
static inline void pad_int(int v, int width, char pad, char* out) {
    char tmp[16]; int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    else {
        bool neg = v < 0; uint32_t u = neg ? (uint32_t)(-v) : (uint32_t)v;
        while (u) { tmp[n++] = '0' + (u % 10); u /= 10; }
        if (neg) tmp[n++] = '-';
    }
    int pad_count = (width > n) ? width - n : 0;
    int o = 0;
    while (pad_count--) out[o++] = pad;
    while (n--) out[o++] = tmp[n];
    out[o] = '\0';
}

// Draw a chunky 3-D button face. Used by calculator, paint, etc.
static inline void draw_button(int bx, int by, int bw, int bh, bool pressed,
                               uint32_t face = ColorPalette::BUTTON_FACE) {
    using namespace ColorPalette;
    uint32_t hi = pressed ? BUTTON_SHADOW    : BUTTON_HIGHLIGHT;
    uint32_t lo = pressed ? BUTTON_HIGHLIGHT : BUTTON_SHADOW;
    draw_rect_filled(bx,     by,     bw, 1,  hi);
    draw_rect_filled(bx,     by,     1,  bh, hi);
    draw_rect_filled(bx + 1, by + bh - 1, bw - 1, 1, lo);
    draw_rect_filled(bx + bw - 1, by + 1,     1,      bh - 1, lo);
    draw_rect_filled(bx + 1, by + 1, bw - 2, bh - 2, face);
}

// Center a string within a rect — 8-px-wide font.
static inline void draw_string_centered(const char* s, int bx, int by, int bw, int bh, uint32_t color) {
    int n = 0; while (s[n]) n++;
    int sx = bx + (bw - n * 8) / 2;
    int sy = by + (bh - 8) / 2;
    draw_string(s, sx, sy, color);
}

#endif // DESKTOP_BASE_WINDOW_H
