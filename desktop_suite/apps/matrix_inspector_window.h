// =====================================================================
// apps/matrix_inspector_window.h — visual frontend for matrix_array.h
// =====================================================================
//
// Tabs along the top to switch between A.npa / B.npa / C.npa. Cell grid
// shows current values, R/W/RX/TX checkboxes show capability bits, and
// a "gemm A·B→C" button runs the blocked multiplier.
//
// Click on the grid to highlight a cell. Click tabs to switch arrays.
// Click the GEMM button (right side of toolbar) to recompute C.
//
// Depends on:
//   matrix_array.h (header-only) sitting next to kernel.cpp

#ifndef DESKTOP_MATRIX_INSPECTOR_H
#define DESKTOP_MATRIX_INSPECTOR_H

#include "../base_window.h"
#include "../../matrix_array.h"

class MatrixInspectorWindow : public BaseAppWindow {
public:
    MatrixInspectorWindow(int x, int y)
        : BaseAppWindow(x, y, 460, 360, "matrix — array inspector"),
          tab_(0), sel_r_(0), sel_c_(0), have_data_(false),
          data_(nullptr), tick_(0)
    {
        reload();
    }
    ~MatrixInspectorWindow() override { delete[] (uint8_t*)data_; }

    uint32_t bg_color() const override { return 0x101820; }

    void update() override {
        // Refresh every ~30 frames in case a terminal command changed
        // disk state behind our back.
        if (++tick_ % 30 == 0) reload();
    }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;

        // ----- tabs + GEMM button -----
        int tabh = 22;
        const char* TABS[3] = { "A.npa", "B.npa", "C.npa" };
        int tw = 64;
        for (int i = 0; i < 3; i++) {
            int bx = cx + 8 + i * (tw + 4);
            int by = cy + 6;
            bool active = (i == tab_);
            draw_button(bx, by, tw, tabh, active, active ? 0xFFFFFF : 0xC0C0C0);
            draw_string_centered(TABS[i], bx, by, tw, tabh, TEXT_BLACK);
            tab_rects_[i] = { bx, by, tw, tabh };
        }
        // GEMM button (right)
        const char* glabel = "gemm A.B -> C";
        int gw = 130;
        gemm_rect_ = { cx + cw - gw - 8, cy + 6, gw, tabh };
        draw_button(gemm_rect_.x, gemm_rect_.y, gw, tabh, false, 0xFFC080);
        draw_string_centered(glabel, gemm_rect_.x, gemm_rect_.y, gw, tabh, TEXT_BLACK);

        // ----- header line -----
        int header_y = cy + 6 + tabh + 6;
        draw_rect_filled(cx + 8, header_y, cw - 16, 22, 0x000000);
        char hbuf[80];
        if (have_data_) {
            // "<name>  shape=(R,C)  dtype=i32  perms=RWXT  v=N"
            int o = 0;
            for (const char* p = TABS[tab_]; *p; ++p) hbuf[o++] = *p;
            hbuf[o++] = ' '; hbuf[o++] = ' ';
            const char* s1 = "shape=("; for (int i = 0; s1[i]; i++) hbuf[o++] = s1[i];
            char tmp[8];
            int_to_string((int)hdr_.shape[0], tmp); for (int i = 0; tmp[i]; i++) hbuf[o++] = tmp[i];
            hbuf[o++] = ',';
            int_to_string((int)hdr_.shape[1], tmp); for (int i = 0; tmp[i]; i++) hbuf[o++] = tmp[i];
            hbuf[o++] = ')';
            const char* s2 = "  i32  perms=";
            for (int i = 0; s2[i]; i++) hbuf[o++] = s2[i];
            hbuf[o++] = (hdr_.perms & NPA_R)  ? 'R' : '-';
            hbuf[o++] = (hdr_.perms & NPA_W)  ? 'W' : '-';
            hbuf[o++] = (hdr_.perms & NPA_RX) ? 'X' : '-';
            hbuf[o++] = (hdr_.perms & NPA_TX) ? 'T' : '-';
            hbuf[o] = 0;
            draw_string(hbuf, cx + 14, header_y + 7, TEXT_GREEN);
        } else {
            const char* msg = "(no array — `matrix create A 8 8` in terminal)";
            draw_string(msg, cx + 14, header_y + 7, TEXT_GRAY);
        }

        // ----- grid -----
        int grid_top = header_y + 24 + 6;
        int side = ch - (grid_top - cy) - 8;
        int right_rail_w = 110;
        int avail_w = cw - 16 - right_rail_w;
        if (have_data_ && hdr_.rank == 2) {
            uint32_t R = hdr_.shape[0] < 8 ? hdr_.shape[0] : 8;
            uint32_t C = hdr_.shape[1] < 8 ? hdr_.shape[1] : 8;
            int cs = (avail_w / (int)C < side / (int)R)
                     ? avail_w / (int)C : side / (int)R;
            if (cs < 14) cs = 14;
            int gw = cs * C, gh = cs * R;
            int gx = cx + 8;
            int gy = grid_top;
            draw_rect_filled(gx, gy, gw, gh, 0x000000);
            const int32_t* a = (const int32_t*)data_;
            char nb[12];
            for (uint32_t j = 0; j < R; j++) {
                for (uint32_t i = 0; i < C; i++) {
                    int bx = gx + (int)i * cs;
                    int by = gy + (int)j * cs;
                    bool selected = ((int)j == sel_r_ && (int)i == sel_c_);
                    bool tile_edge_r = ((j + 1) % hdr_.tile_r == 0);
                    bool tile_edge_c = ((i + 1) % hdr_.tile_c == 0);
                    if (selected) draw_rect_filled(bx, by, cs, cs, 0xC0E0FF);
                    int v = a[j * hdr_.shape[1] + i];
                    int_to_string(v, nb);
                    uint32_t fg = selected ? TEXT_BLACK : (v == 0 ? 0x404040 : 0xB0FFC0);
                    draw_string_centered(nb, bx, by, cs, cs, fg);
                    if (tile_edge_c) draw_rect_filled(bx + cs - 1, by, 1, cs, 0x303030);
                    if (tile_edge_r) draw_rect_filled(bx, by + cs - 1, cs, 1, 0x303030);
                }
            }
            // border
            for (int i = 0; i < gw; i++) {
                put_pixel_back(gx + i, gy,     0x404040);
                put_pixel_back(gx + i, gy + gh, 0x404040);
            }
            for (int j = 0; j < gh; j++) {
                put_pixel_back(gx,        gy + j, 0x404040);
                put_pixel_back(gx + gw,   gy + j, 0x404040);
            }
            grid_x_ = gx; grid_y_ = gy; cell_s_ = cs;
            grid_rows_ = R; grid_cols_ = C;

            // ----- right rail: perms + selection -----
            int rx = cx + cw - right_rail_w - 4;
            int ry = grid_top;
            const char* h1 = "perms";
            draw_string(h1, rx, ry, TEXT_WHITE);
            const char* PLBL[4] = { "R  read", "W  write", "X  exec", "T  transmit" };
            uint16_t bits[4]   = { NPA_R, NPA_W, NPA_RX, NPA_TX };
            for (int i = 0; i < 4; i++) {
                int by = ry + 14 + i * 14;
                int on = (hdr_.perms & bits[i]) ? 1 : 0;
                draw_rect_filled(rx, by, 10, 10, on ? 0x40C040 : 0x303030);
                for (int k = 0; k < 10; k++) {
                    put_pixel_back(rx + k, by,     0xA0A0A0);
                    put_pixel_back(rx,     by + k, 0xA0A0A0);
                }
                draw_string(PLBL[i], rx + 16, by + 1, TEXT_WHITE);
            }
            char sbuf[32];
            const char* s3 = "sel: [";
            int o = 0;
            for (int i = 0; s3[i]; i++) sbuf[o++] = s3[i];
            int_to_string(sel_r_, nb); for (int i = 0; nb[i]; i++) sbuf[o++] = nb[i];
            sbuf[o++] = ',';
            int_to_string(sel_c_, nb); for (int i = 0; nb[i]; i++) sbuf[o++] = nb[i];
            sbuf[o++] = ']'; sbuf[o] = 0;
            draw_string(sbuf, rx, ry + 90, TEXT_GRAY);
            if ((int)R > sel_r_ && (int)C > sel_c_) {
                const int32_t* a2 = (const int32_t*)data_;
                int v = a2[sel_r_ * hdr_.shape[1] + sel_c_];
                char vb[16]; int_to_string(v, vb);
                draw_string(vb, rx, ry + 104, TEXT_GREEN);
            }
        }
    }

    void on_click(int rx, int ry) override {
        int ax = x + rx, ay = y + APP_TITLEBAR_H + ry;
        // Tabs
        for (int i = 0; i < 3; i++) {
            Rect& r = tab_rects_[i];
            if (ax >= r.x && ax < r.x + r.w && ay >= r.y && ay < r.y + r.h) {
                if (tab_ != i) { tab_ = i; reload(); sel_r_ = sel_c_ = 0; }
                return;
            }
        }
        // GEMM
        if (ax >= gemm_rect_.x && ax < gemm_rect_.x + gemm_rect_.w
            && ay >= gemm_rect_.y && ay < gemm_rect_.y + gemm_rect_.h) {
            npa_gemm("A.npa", "B.npa", "C.npa");
            tab_ = 2; reload(); return;
        }
        // Grid
        if (have_data_ && cell_s_ > 0
            && ax >= grid_x_ && ax < grid_x_ + cell_s_ * (int)grid_cols_
            && ay >= grid_y_ && ay < grid_y_ + cell_s_ * (int)grid_rows_) {
            sel_c_ = (ax - grid_x_) / cell_s_;
            sel_r_ = (ay - grid_y_) / cell_s_;
        }
    }

    void on_key_press(char c) override {
        if      (c == '1') { tab_ = 0; reload(); }
        else if (c == '2') { tab_ = 1; reload(); }
        else if (c == '3') { tab_ = 2; reload(); }
        else if (c == 'g' || c == 'G') {
            npa_gemm("A.npa", "B.npa", "C.npa");
            tab_ = 2; reload();
        }
    }

private:
    struct Rect { int x, y, w, h; };
    int tab_;
    int sel_r_, sel_c_;
    bool have_data_;
    ArrayHeader hdr_;
    void* data_;
    uint32_t tick_;

    Rect tab_rects_[3]{};
    Rect gemm_rect_{};
    int grid_x_ = 0, grid_y_ = 0, cell_s_ = 0;
    uint32_t grid_rows_ = 0, grid_cols_ = 0;

    void reload() {
        delete[] (uint8_t*)data_; data_ = nullptr;
        have_data_ = false;
        const char* names[3] = { "A.npa", "B.npa", "C.npa" };
        if (npa_load(names[tab_], &hdr_, &data_) == 0) have_data_ = true;
    }
};

#endif
