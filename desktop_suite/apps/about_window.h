// =====================================================================
// apps/about_window.h — About dialog
// =====================================================================

#ifndef DESKTOP_ABOUT_WINDOW_H
#define DESKTOP_ABOUT_WINDOW_H

#include "../base_window.h"

class AboutWindow : public BaseAppWindow {
public:
    AboutWindow(int x, int y)
        : BaseAppWindow(x, y, 360, 240, "About storage-OS") {}

    uint32_t bg_color() const override { return ColorPalette::BUTTON_FACE; }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;

        // Logo block
        int lw = 60;
        draw_rect_filled(cx + 16, cy + 16, lw, lw, 0x000080);
        draw_string_centered("OS", cx + 16, cy + 16, lw, lw, TEXT_WHITE);

        int tx = cx + 16 + lw + 12;
        draw_string("storage-OS",  tx, cy + 18, TEXT_BLACK);
        draw_string("build 0.3-bochs", tx, cy + 32, TEXT_GRAY);
        draw_string("custom i386 kernel", tx, cy + 50, TEXT_BLACK);
        draw_string("Bochs CPU emulator slot", tx, cy + 64, TEXT_BLACK);

        int y0 = cy + 90;
        const char* LINES[] = {
            "cpu        i386 (single vCPU)",
            "filesystem FAT32  /dev/sd[ab]",
            "windowing  Window + WindowManager",
            "arrays     matrix_array.h  R/W/RX/TX caps",
            "exit       outb 0xE8   (Bochs ELFs)",
            nullptr
        };
        for (int i = 0; LINES[i]; i++) {
            draw_string(LINES[i], cx + 16, y0 + i * 12, TEXT_BLACK);
        }

        const char* foot = "press any key to dismiss";
        draw_string_centered(foot, cx, cy + ch - 16, cw, 8, TEXT_GRAY);
    }

    void on_key_press(char /*c*/) override { close(); }
    void on_click(int /*rx*/, int /*ry*/) override { close(); }
};

#endif
