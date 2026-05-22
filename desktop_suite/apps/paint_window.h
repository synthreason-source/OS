// =====================================================================
// apps/paint_window.h — pixel paint canvas
// =====================================================================
//
// Click+drag on the canvas to draw. Click a palette swatch to choose a
// color. Brush is 1×1 by default; cycle brush size with Tab. Pressing
// 'c' clears the canvas. The canvas is backed by an in-window byte
// array — one palette index per cell so it survives redraws without
// reading back from the framebuffer.

#ifndef DESKTOP_PAINT_WINDOW_H
#define DESKTOP_PAINT_WINDOW_H

#include "../base_window.h"

class PaintWindow : public BaseAppWindow {
public:
    PaintWindow(int x, int y)
        : BaseAppWindow(x, y, 360, 280, "Paint"),
          color_idx_(0), brush_(1), dragging_(false),
          last_rx_(-1), last_ry_(-1)
    {
        for (int i = 0; i < CW * CH; i++) cells_[i] = 0xFF; // 0xFF = empty
    }

    uint32_t bg_color() const override { return ColorPalette::BUTTON_FACE; }

    void update() override {}

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;
        // ----- palette strip (left) -----
        int pal_x = cx + 4;
        int pal_y = cy + 4;
        int sw = 22;
        for (int i = 0; i < (int)(sizeof(PALETTE) / sizeof(PALETTE[0])); i++) {
            int row = i / 2, col = i % 2;
            int bx = pal_x + col * (sw + 2);
            int by = pal_y + row * (sw + 2);
            draw_button(bx, by, sw, sw, false, PALETTE[i]);
            if (i == color_idx_) {
                // selected highlight border
                for (int k = 0; k < sw; k++) {
                    put_pixel_back(bx + k, by - 1,        TEXT_BLACK);
                    put_pixel_back(bx + k, by + sw,       TEXT_BLACK);
                    put_pixel_back(bx - 1, by + k,        TEXT_BLACK);
                    put_pixel_back(bx + sw, by + k,       TEXT_BLACK);
                }
            }
        }

        // Brush size readout
        char buf[16];
        const char* prefix = "brush:";
        int p = 0; while (prefix[p]) { buf[p] = prefix[p]; p++; }
        buf[p++] = ' '; buf[p++] = '0' + brush_; buf[p] = 0;
        draw_string(buf, pal_x, cy + ch - 14, TEXT_BLACK);

        // ----- canvas -----
        int canvas_x = pal_x + 2 * (sw + 2) + 6;
        int canvas_y = cy + 4;
        int canvas_w = cx + cw - canvas_x - 4;
        int canvas_h = ch - 8;
        canvas_x_ = canvas_x; canvas_y_ = canvas_y;
        canvas_w_ = canvas_w; canvas_h_ = canvas_h;

        // Cell size: pick the largest integer scale that fits.
        int scale_x = canvas_w / CW;
        int scale_y = canvas_h / CH;
        cell_scale_ = scale_x < scale_y ? scale_x : scale_y;
        if (cell_scale_ < 2) cell_scale_ = 2;

        // White background
        draw_rect_filled(canvas_x, canvas_y,
                         CW * cell_scale_, CH * cell_scale_, 0xFFFFFF);

        // Paint cells
        for (int j = 0; j < CH; j++) {
            for (int i = 0; i < CW; i++) {
                uint8_t v = cells_[j * CW + i];
                if (v == 0xFF) continue;
                draw_rect_filled(canvas_x + i * cell_scale_,
                                 canvas_y + j * cell_scale_,
                                 cell_scale_, cell_scale_,
                                 PALETTE[v & 0x0F]);
            }
        }

        // 1-px frame around canvas
        for (int i = 0; i < CW * cell_scale_; i++) {
            put_pixel_back(canvas_x + i, canvas_y - 1,                TEXT_BLACK);
            put_pixel_back(canvas_x + i, canvas_y + CH * cell_scale_, TEXT_BLACK);
        }
        for (int i = 0; i < CH * cell_scale_; i++) {
            put_pixel_back(canvas_x - 1,                canvas_y + i, TEXT_BLACK);
            put_pixel_back(canvas_x + CW * cell_scale_, canvas_y + i, TEXT_BLACK);
        }
    }

    void on_click(int rx, int ry) override {
        using namespace ColorPalette;
        int ax = x + rx;
        int ay = y + APP_TITLEBAR_H + ry;

        // Palette hit?
        int pal_x = x + 4;
        int pal_y = y + APP_TITLEBAR_H + 4;
        int sw = 22;
        int npal = (int)(sizeof(PALETTE) / sizeof(PALETTE[0]));
        for (int i = 0; i < npal; i++) {
            int row = i / 2, col = i % 2;
            int bx = pal_x + col * (sw + 2);
            int by = pal_y + row * (sw + 2);
            if (ax >= bx && ax < bx + sw && ay >= by && ay < by + sw) {
                color_idx_ = i; return;
            }
        }

        // Canvas hit? Paint a stamp.
        if (cell_scale_ > 0
            && ax >= canvas_x_ && ax < canvas_x_ + CW * cell_scale_
            && ay >= canvas_y_ && ay < canvas_y_ + CH * cell_scale_) {
            int ci = (ax - canvas_x_) / cell_scale_;
            int cj = (ay - canvas_y_) / cell_scale_;
            stamp(ci, cj);
            last_rx_ = ci; last_ry_ = cj; dragging_ = true;
        }
    }

    void on_key_press(char c) override {
        if (c == 'c' || c == 'C') {
            for (int i = 0; i < CW * CH; i++) cells_[i] = 0xFF;
        } else if (c == 9 /*Tab*/) {
            brush_ = (brush_ % 4) + 1;
        } else if (c == '[') { color_idx_ = (color_idx_ + 15) % 16; }
        else  if (c == ']') { color_idx_ = (color_idx_ + 1) % 16; }
    }

private:
    static constexpr int CW = 48;
    static constexpr int CH = 32;
    static constexpr uint32_t PALETTE[16] = {
        0x000000, 0xFFFFFF, 0xFF0000, 0x00C000,
        0x0000FF, 0xFFC000, 0xFF00FF, 0x00FFFF,
        0x808080, 0xC0C0C0, 0x800000, 0x008000,
        0x000080, 0x808000, 0x800080, 0x008080,
    };
    uint8_t cells_[CW * CH];

    int color_idx_;
    int brush_;
    bool dragging_;
    int last_rx_, last_ry_;

    // Canvas rect cached after draw_content for hit-tests.
    int canvas_x_, canvas_y_, canvas_w_, canvas_h_;
    int cell_scale_ = 0;

    void stamp(int ci, int cj) {
        for (int dy = -(brush_ - 1) / 2; dy <= brush_ / 2; dy++) {
            for (int dx = -(brush_ - 1) / 2; dx <= brush_ / 2; dx++) {
                int xi = ci + dx, yi = cj + dy;
                if (xi >= 0 && xi < CW && yi >= 0 && yi < CH)
                    cells_[yi * CW + xi] = (uint8_t)color_idx_;
            }
        }
    }
};

constexpr uint32_t PaintWindow::PALETTE[16];

#endif
