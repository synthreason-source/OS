// =====================================================================
// apps/calculator_window.h — 4-function calculator
// =====================================================================
//
// 4×5 button grid (4 columns, top row is the display).
// State: accumulator, pending operator, on-deck operand, flags.
// Integer-only — fits the rest of the kernel's integer-arithmetic
// vocabulary. Replace with int64 / fixed-point if you want decimals.

#ifndef DESKTOP_CALCULATOR_WINDOW_H
#define DESKTOP_CALCULATOR_WINDOW_H

#include "../base_window.h"

class CalculatorWindow : public BaseAppWindow {
public:
    CalculatorWindow(int x, int y)
        : BaseAppWindow(x, y, 220, 280, "Calculator"),
          display_(0), pending_(0), op_('\0'),
          start_new_(true), error_(false), pressed_idx_(-1), press_ttl_(0) {}

    uint32_t bg_color() const override { return ColorPalette::BUTTON_FACE; }

    void update() override {
        // Auto-release pressed visual after ~6 frames.
        if (press_ttl_ > 0 && --press_ttl_ == 0) pressed_idx_ = -1;
    }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;
        // ----- display -----
        int dh = 36;
        draw_rect_filled(cx + 8, cy + 8, cw - 16, dh, 0x101010);
        for (int i = 0; i < cw - 16; i++) put_pixel_back(cx + 8 + i, cy + 8,        0x404040);
        for (int i = 0; i < dh;       i++) put_pixel_back(cx + 8,     cy + 8 + i,    0x404040);

        char buf[24];
        if (error_) {
            const char* e = "ERROR"; int n = 0; while (e[n]) n++;
            draw_string(e, cx + cw - 16 - n * 8 - 6, cy + 8 + dh/2 - 4, BUTTON_CLOSE);
        } else {
            int_to_string(display_, buf);
            int n = 0; while (buf[n]) n++;
            draw_string(buf, cx + cw - 16 - n * 8 - 6, cy + 8 + dh/2 - 4, TEXT_GREEN);
        }
        // Pending-op indicator in top-left of display
        if (op_) { char p[2] = { op_, 0 }; draw_string(p, cx + 14, cy + 12, TEXT_GRAY); }

        // ----- buttons -----
        layout_buttons(cx, cy + 8 + dh + 6, cw, ch - 8 - dh - 6);
        for (int i = 0; i < NUM_BTNS; i++) {
            Btn& b = btns_[i];
            bool pressed = (i == pressed_idx_);
            uint32_t face = button_face(b.label[0]);
            draw_button(b.bx, b.by, b.bw, b.bh, pressed, face);
            uint32_t fg = (b.label[0] >= '0' && b.label[0] <= '9') ? TEXT_BLACK : TEXT_BLACK;
            draw_string_centered(b.label, b.bx, b.by, b.bw, b.bh, fg);
        }
    }

    void on_click(int rx, int ry) override {
        layout_buttons(x, y + APP_TITLEBAR_H + 8 + 36 + 6, w, 0); // refresh rects
        int ax = x + rx;
        int ay = y + APP_TITLEBAR_H + ry;
        for (int i = 0; i < NUM_BTNS; i++) {
            Btn& b = btns_[i];
            if (ax >= b.bx && ax < b.bx + b.bw && ay >= b.by && ay < b.by + b.bh) {
                press_button(i);
                return;
            }
        }
    }

    void on_key_press(char c) override {
        if (c >= '0' && c <= '9') { input_digit(c - '0'); return; }
        if (c == '+' || c == '-' || c == '*' || c == '/') { set_op(c); return; }
        if (c == '=' || c == '\n' || c == '\r') { equals(); return; }
        if (c == 'c' || c == 'C' || c == 27 /*ESC*/) { clear_all(); return; }
        if (c == 8 /*BS*/) { backspace(); return; }
    }

private:
    static constexpr int NUM_BTNS = 20;
    struct Btn { const char* label; int bx, by, bw, bh; };
    Btn btns_[NUM_BTNS];

    int display_;
    int pending_;
    char op_;
    bool start_new_;
    bool error_;
    int  pressed_idx_;
    int  press_ttl_;

    static uint32_t button_face(char first) {
        using namespace ColorPalette;
        if (first == '+' || first == '-' || first == '*' || first == '/' || first == '=') return 0xFFC080;
        if (first == 'C' || first == 'B') return 0xFFB0B0;
        return BUTTON_FACE;
    }

    void layout_buttons(int cx, int btop, int cw, int /*ch*/) {
        // Layout pattern (row-major):
        //   C   B   /   *
        //   7   8   9   -
        //   4   5   6   +
        //   1   2   3   =
        //   0   0   .   =   (0 spans, '.' and '=' duplicates merged)
        // Simpler: keep 4 cols × 5 rows = 20 buttons; some labels repeat to fill.
        static const char* LBL[NUM_BTNS] = {
            "C","BS","/", "*",
            "7","8","9","-",
            "4","5","6","+",
            "1","2","3","=",
            "0","00","",  "=",
        };
        int pad = 6;
        int bw = (cw - 8 - 8 - pad * 3) / 4;
        int bh = 36;
        for (int r = 0; r < 5; r++) {
            for (int c = 0; c < 4; c++) {
                int idx = r * 4 + c;
                btns_[idx].label = LBL[idx];
                btns_[idx].bx = cx + 8 + c * (bw + pad);
                btns_[idx].by = btop + r * (bh + pad);
                btns_[idx].bw = bw;
                btns_[idx].bh = bh;
            }
        }
    }

    void press_button(int i) {
        pressed_idx_ = i; press_ttl_ = 6;
        const char* lbl = btns_[i].label;
        if (!lbl || !lbl[0]) return;
        if (lbl[0] >= '0' && lbl[0] <= '9') {
            input_digit(lbl[0] - '0');
            if (lbl[1] == '0') input_digit(0); // "00"
        } else if (lbl[0] == 'C') { clear_all(); }
        else if (lbl[0] == 'B') { backspace(); }
        else if (lbl[0] == '=') { equals(); }
        else if (lbl[0] == '+' || lbl[0] == '-' || lbl[0] == '*' || lbl[0] == '/') {
            set_op(lbl[0]);
        }
    }

    void input_digit(int d) {
        if (error_) clear_all();
        if (start_new_) { display_ = 0; start_new_ = false; }
        if (display_ > 99999999) return; // overflow guard
        display_ = display_ * 10 + d;
    }
    void backspace() { if (!start_new_) display_ /= 10; }
    void set_op(char c) { commit_pending(); op_ = c; start_new_ = true; }
    void equals()       { commit_pending(); op_ = '\0'; start_new_ = true; }
    void clear_all()    { display_ = 0; pending_ = 0; op_ = '\0'; start_new_ = true; error_ = false; }

    void commit_pending() {
        if (op_ == '\0') { pending_ = display_; return; }
        int r;
        switch (op_) {
            case '+': r = pending_ + display_; break;
            case '-': r = pending_ - display_; break;
            case '*': r = pending_ * display_; break;
            case '/': if (display_ == 0) { error_ = true; return; }
                      r = pending_ / display_; break;
            default:  r = display_; break;
        }
        pending_ = r;
        display_ = r;
    }
};

#endif
