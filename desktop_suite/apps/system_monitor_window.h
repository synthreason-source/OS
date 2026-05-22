// =====================================================================
// apps/system_monitor_window.h — live CPU / RAM / process readout
// =====================================================================
//
// A small system dashboard that ticks every frame:
//   • CPU bar driven by a synthetic load estimate (frame jitter)
//   • RAM bar (placeholder — wire to your real heap counters)
//   • Uptime (RTC-derived) and tick counter
//   • Rolling 64-sample CPU history graph
//
// The two "wire your kernel state here" hooks are read_cpu_load_pct()
// and read_ram_used_kb(). Replace those with calls into your real
// kernel state when convenient — both default to harmless synthetic
// values so this window compiles standalone.

#ifndef DESKTOP_SYSMON_WINDOW_H
#define DESKTOP_SYSMON_WINDOW_H

#include "../base_window.h"

class SystemMonitorWindow : public BaseAppWindow {
public:
    SystemMonitorWindow(int x, int y)
        : BaseAppWindow(x, y, 340, 240, "System Monitor"),
          head_(0), tick_(0), boot_sec_(-1)
    {
        for (int i = 0; i < HIST; i++) hist_[i] = 0;
    }

    uint32_t bg_color() const override { return 0x101820; }

    void update() override {
        tick_++;
        if (tick_ % 6 == 0) {
            uint8_t pct = read_cpu_load_pct();
            hist_[head_] = pct;
            head_ = (head_ + 1) % HIST;
        }
    }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;

        // ----- header row: CPU + RAM bars -----
        int bar_h = 18;
        int row_y = cy + 10;
        uint8_t cpu_pct = read_cpu_load_pct();
        uint32_t ram_kb = read_ram_used_kb();
        uint32_t ram_max_kb = read_ram_total_kb();

        draw_string("CPU", cx + 8, row_y + 5, TEXT_WHITE);
        draw_bar(cx + 44, row_y, cw - 100, bar_h, cpu_pct, 100,
                 0x00C040, 0x202020);
        char b1[16]; pad_int(cpu_pct, 3, ' ', b1); b1[3] = '%'; b1[4] = 0;
        draw_string(b1, cx + cw - 50, row_y + 5, TEXT_WHITE);

        row_y += bar_h + 8;
        draw_string("RAM", cx + 8, row_y + 5, TEXT_WHITE);
        uint32_t cur = ram_max_kb ? (ram_kb * 100 / ram_max_kb) : 0;
        draw_bar(cx + 44, row_y, cw - 100, bar_h, cur, 100,
                 0x4080FF, 0x202020);
        char b2[20];
        pad_int((int)(ram_kb / 1024), 4, ' ', b2);
        b2[4] = 'M'; b2[5] = 0;
        draw_string(b2, cx + cw - 50, row_y + 5, TEXT_WHITE);

        // ----- graph -----
        int graph_top = row_y + bar_h + 14;
        int graph_h = ch - (graph_top - cy) - 36;
        if (graph_h < 30) graph_h = 30;
        draw_rect_filled(cx + 8, graph_top, cw - 16, graph_h, 0x000000);
        // grid lines
        for (int g = 1; g < 4; g++) {
            int gy = graph_top + (graph_h * g) / 4;
            draw_rect_filled(cx + 8, gy, cw - 16, 1, 0x182030);
        }
        // plot
        int n = cw - 16;
        for (int xi = 0; xi < n && xi < HIST; xi++) {
            int idx = (head_ - 1 - xi + HIST) % HIST;
            int v = hist_[idx];
            int h = (graph_h * v) / 100;
            draw_rect_filled(cx + 8 + (n - 1 - xi), graph_top + (graph_h - h),
                             1, h, 0x00C040);
        }
        // frame
        for (int i = 0; i < cw - 16; i++) {
            put_pixel_back(cx + 8 + i, graph_top,             0x303030);
            put_pixel_back(cx + 8 + i, graph_top + graph_h,   0x303030);
        }
        for (int j = 0; j < graph_h; j++) {
            put_pixel_back(cx + 8,            graph_top + j,  0x303030);
            put_pixel_back(cx + 8 + cw - 17,  graph_top + j,  0x303030);
        }

        // ----- footer: uptime + tick -----
        RTC_Time t = read_rtc();
        int now_sec = (int)t.hour * 3600 + (int)t.minute * 60 + (int)t.second;
        if (boot_sec_ < 0) boot_sec_ = now_sec;
        int up = now_sec - boot_sec_;
        if (up < 0) up += 24 * 3600;

        char buf[32];
        const char* l = "uptime:";
        int o = 0; while (l[o]) { buf[o] = l[o]; o++; }
        buf[o++] = ' ';
        char hh[8], mm[8], ss[8];
        pad_int(up / 3600, 2, '0', hh);
        pad_int((up / 60) % 60, 2, '0', mm);
        pad_int(up % 60, 2, '0', ss);
        for (int k = 0; hh[k]; k++) buf[o++] = hh[k];
        buf[o++] = ':';
        for (int k = 0; mm[k]; k++) buf[o++] = mm[k];
        buf[o++] = ':';
        for (int k = 0; ss[k]; k++) buf[o++] = ss[k];
        buf[o] = 0;
        draw_string(buf, cx + 8, cy + ch - 24, TEXT_WHITE);

        char tbuf[32];
        const char* l2 = "frame:";
        int o2 = 0; while (l2[o2]) { tbuf[o2] = l2[o2]; o2++; }
        tbuf[o2++] = ' ';
        char nb[12]; int_to_string((int)tick_, nb);
        for (int k = 0; nb[k]; k++) tbuf[o2++] = nb[k];
        tbuf[o2] = 0;
        draw_string(tbuf, cx + cw - 130, cy + ch - 24, TEXT_GRAY);
    }

private:
    static constexpr int HIST = 96;
    uint8_t hist_[HIST];
    int head_;
    uint32_t tick_;
    int boot_sec_;

    // ----- pluggable kernel hooks --------------------------------------
    // Replace these stubs with real kernel counters when convenient.
    // The window will pick up the new values automatically.

    static uint8_t read_cpu_load_pct() {
        // Synthetic: jitter around 35% so the graph has a heartbeat.
        static uint32_t s = 0; s = s * 1103515245u + 12345u;
        int j = (int)((s >> 16) & 31) - 15;
        int v = 35 + j;
        if (v < 0) v = 0; if (v > 100) v = 100;
        return (uint8_t)v;
    }
    static uint32_t read_ram_used_kb()  { return 4096; }   // 4 MiB placeholder
    static uint32_t read_ram_total_kb() { return 32768; }  // 32 MiB placeholder

    // ----- helpers -----------------------------------------------------
    static void draw_bar(int bx, int by, int bw, int bh, int v, int vmax,
                         uint32_t fg, uint32_t bg) {
        draw_rect_filled(bx, by, bw, bh, bg);
        if (vmax <= 0) return;
        int fill = (bw * v) / vmax;
        if (fill > bw) fill = bw;
        draw_rect_filled(bx, by, fill, bh, fg);
        for (int i = 0; i < bw; i++) {
            put_pixel_back(bx + i, by,      0x404040);
            put_pixel_back(bx + i, by + bh, 0x404040);
        }
        for (int j = 0; j < bh; j++) {
            put_pixel_back(bx,        by + j, 0x404040);
            put_pixel_back(bx + bw,   by + j, 0x404040);
        }
    }
};

#endif
