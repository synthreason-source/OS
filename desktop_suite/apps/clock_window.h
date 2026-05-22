// =====================================================================
// apps/clock_window.h — analog + digital clock
// =====================================================================
//
// Reads RTC every frame, renders an analog face with hour/minute/second
// hands plus a digital readout below. Self-redraws on tick.

#ifndef DESKTOP_CLOCK_WINDOW_H
#define DESKTOP_CLOCK_WINDOW_H

#include "../base_window.h"

// Drawing primitives and types (RTC_Time, gfx_abs, put_pixel_back, read_rtc)
// are provided by kernel.cpp, which includes this header.

// Fixed-point cos/sin via a 60-step lookup table.  Indices 0..59
// correspond to a full clockwise revolution (matching seconds on the
// face). Values are scaled by 1024 — divide by 1024 after the multiply.
//   table[i] = (sin(2*pi*i/60) * 1024, -cos(2*pi*i/60) * 1024)
// Hand goes UP at i=0, RIGHT at i=15, DOWN at i=30, LEFT at i=45.
static const int16_t CLOCK_SIN60[60] = {
       0,  107,  213,  316,  416,  512,  602,  685,  761,  828,
     886,  933,  971,  998, 1014, 1019, 1014,  998,  971,  933,
     886,  828,  761,  685,  602,  512,  416,  316,  213,  107,
       0, -107, -213, -316, -416, -512, -602, -685, -761, -828,
    -886, -933, -971, -998,-1014,-1019,-1014, -998, -971, -933,
    -886, -828, -761, -685, -602, -512, -416, -316, -213, -107
};
static const int16_t CLOCK_COS60[60] = {
   -1024,-1019,-1014, -998, -971, -933, -886, -828, -761, -685,
    -602, -512, -416, -316, -213, -107,    0,  107,  213,  316,
     416,  512,  602,  685,  761,  828,  886,  933,  971,  998,
    1014, 1019, 1014,  998,  971,  933,  886,  828,  761,  685,
     602,  512,  416,  316,  213,  107,    0, -107, -213, -316,
    -416, -512, -602, -685, -761, -828, -886, -933, -971, -998
};

class ClockWindow : public BaseAppWindow {
public:
    ClockWindow(int x, int y)
        : BaseAppWindow(x, y, 220, 260, "Clock") {}

    uint32_t bg_color() const override { return ColorPalette::BUTTON_FACE; }

    void update() override {
        // The kernel's frame loop calls draw() unconditionally — but to
        // be polite about wasted work we re-stat RTC only every ~16
        // frames. (At ~30fps this is a 0.5s update; the second hand
        // still moves visibly because draw() runs every frame.)
    }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;
        RTC_Time t = read_rtc();

        // ----- analog face -----
        int face_h = ch - 38;          // leave a strip for digital
        int radius = (face_h < cw ? face_h : cw) / 2 - 8;
        int ccx = cx + cw / 2;
        int ccy = cy + face_h / 2 + 2;

        draw_disc(ccx, ccy, radius,     0x303030);
        draw_disc(ccx, ccy, radius - 1, 0xE8E8E8);

        // Hour ticks
        for (int i = 0; i < 12; i++) {
            int idx = (i * 5) % 60;
            int sx = ccx + (CLOCK_SIN60[idx] * (radius - 3)) / 1024;
            int sy = ccy + (CLOCK_COS60[idx] * (radius - 3)) / 1024;
            int ex = ccx + (CLOCK_SIN60[idx] * (radius - 10)) / 1024;
            int ey = ccy + (CLOCK_COS60[idx] * (radius - 10)) / 1024;
            draw_thick_line(sx, sy, ex, ey, 0x202020);
        }

        // Hour hand
        int hour_idx = ((t.hour % 12) * 5 + t.minute / 12) % 60;
        draw_thick_line(ccx, ccy,
                        ccx + (CLOCK_SIN60[hour_idx] * radius * 11/20) / 1024,
                        ccy + (CLOCK_COS60[hour_idx] * radius * 11/20) / 1024,
                        0x202020);

        // Minute hand
        int min_idx = t.minute % 60;
        draw_thick_line(ccx, ccy,
                        ccx + (CLOCK_SIN60[min_idx] * radius * 16/20) / 1024,
                        ccy + (CLOCK_COS60[min_idx] * radius * 16/20) / 1024,
                        0x202020);

        // Second hand — thin, red
        int sec_idx = t.second % 60;
        draw_line_1px(ccx, ccy,
                      ccx + (CLOCK_SIN60[sec_idx] * radius * 18/20) / 1024,
                      ccy + (CLOCK_COS60[sec_idx] * radius * 18/20) / 1024,
                      BUTTON_CLOSE);

        // Center cap
        draw_disc(ccx, ccy, 3, 0x202020);

        // ----- digital -----
        char buf[20];
        pad_int(t.hour,   2, '0', buf + 0);  buf[2]  = ':';
        pad_int(t.minute, 2, '0', buf + 3);  buf[5]  = ':';
        pad_int(t.second, 2, '0', buf + 6);  buf[8]  = '\0';
        int dy = cy + face_h + 8;
        draw_rect_filled(cx + 6, dy - 2, cw - 12, 22, 0x101010);
        draw_string_centered(buf, cx + 6, dy - 2, cw - 12, 22, TEXT_GREEN);

        char dbuf[20];
        pad_int(t.year, 4, '0', dbuf + 0);  dbuf[4] = '-';
        pad_int(t.month, 2, '0', dbuf + 5); dbuf[7] = '-';
        pad_int(t.day,  2, '0', dbuf + 8);  dbuf[10] = '\0';
        draw_string_centered(dbuf, cx, dy + 22, cw, 10, TEXT_BLACK);
    }

private:
    // Filled disc via brute-force scanlines — radius is small (<60).
    static void draw_disc(int ccx, int ccy, int r, uint32_t color) {
        for (int dy = -r; dy <= r; dy++) {
            for (int dx = -r; dx <= r; dx++) {
                if (dx * dx + dy * dy <= r * r)
                    put_pixel_back(ccx + dx, ccy + dy, color);
            }
        }
    }

    // 1-pixel Bresenham line.
    static void draw_line_1px(int x0, int y0, int x1, int y1, uint32_t color) {
        int dx = gfx_abs(x1 - x0), dy = gfx_abs(y1 - y0);
        int sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
        int err = dx - dy;
        for (;;) {
            put_pixel_back(x0, y0, color);
            if (x0 == x1 && y0 == y1) break;
            int e2 = 2 * err;
            if (e2 > -dy) { err -= dy; x0 += sx; }
            if (e2 <  dx) { err += dx; y0 += sy; }
        }
    }

    // 3-pixel thick line — draw_line_1px twice with a 1-px offset.
    static void draw_thick_line(int x0, int y0, int x1, int y1, uint32_t color) {
        draw_line_1px(x0, y0, x1, y1, color);
        draw_line_1px(x0 + 1, y0, x1 + 1, y1, color);
        draw_line_1px(x0, y0 + 1, x1, y1 + 1, color);
    }
};

#endif
