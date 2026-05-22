// =====================================================================
// apps/minesweeper_window.h — Minesweeper
// =====================================================================
//
// 10×10 board, 15 mines (configurable). Left-click reveals (also routed
// from on_click). Right-click toggles a flag — uses Window's
// on_mouse_right_click override. Press 'n' to start a new game, 'f' to
// toggle flag mode for left clicks (handy on touch / single-button
// pointer setups).

#ifndef DESKTOP_MINESWEEPER_WINDOW_H
#define DESKTOP_MINESWEEPER_WINDOW_H

#include "../base_window.h"

class MinesweeperWindow : public BaseAppWindow {
public:
    MinesweeperWindow(int x, int y)
        : BaseAppWindow(x, y, 270, 320, "Minesweeper"),
          flag_mode_(false), state_(PLAY), rng_(0xCAFEBABE), elapsed_(0)
    {
        new_game();
    }

    uint32_t bg_color() const override { return ColorPalette::BUTTON_FACE; }

    void update() override {
        if (state_ == PLAY && started_) {
            tick_++;
            if (tick_ % 30 == 0) elapsed_++;
        }
    }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;

        // ----- HUD -----
        int hud_h = 28;
        draw_button(cx + 6, cy + 6, cw - 12, hud_h, true, 0xA0A0A0);
        char mine_buf[8]; pad_int(mines_left(), 3, '0', mine_buf);
        char time_buf[8]; pad_int(elapsed_,     3, '0', time_buf);
        draw_rect_filled(cx + 10, cy + 10, 32, hud_h - 8, 0x101010);
        draw_string(mine_buf, cx + 14, cy + 10 + (hud_h - 16)/2, BUTTON_CLOSE);
        draw_rect_filled(cx + cw - 42, cy + 10, 32, hud_h - 8, 0x101010);
        draw_string(time_buf, cx + cw - 38, cy + 10 + (hud_h - 16)/2, BUTTON_CLOSE);

        // Smiley reset button
        int rb = 24;
        int rbx = cx + cw/2 - rb/2;
        int rby = cy + 6 + (hud_h - rb)/2 + 1;
        draw_button(rbx, rby, rb, rb, false, 0xFFD040);
        const char* face = (state_ == WIN) ? "B" : (state_ == LOSE) ? "X" : ":";
        draw_string_centered(face, rbx, rby, rb, rb, TEXT_BLACK);
        reset_btn_x_ = rbx; reset_btn_y_ = rby; reset_btn_s_ = rb;

        // ----- Board -----
        int board_top = cy + 6 + hud_h + 6;
        int avail_h = cy + ch - board_top - 4;
        int avail_w = cw - 12;
        int s = (avail_w / GW < avail_h / GH) ? avail_w / GW : avail_h / GH;
        if (s < 16) s = 16;
        int board_w = s * GW;
        int board_h = s * GH;
        board_x_ = cx + (cw - board_w) / 2;
        board_y_ = board_top;
        cell_s_  = s;

        for (int j = 0; j < GH; j++) {
            for (int i = 0; i < GW; i++) {
                int bx = board_x_ + i * s;
                int by = board_y_ + j * s;
                Cell& c = cells_[j * GW + i];
                if (c.revealed) {
                    draw_rect_filled(bx, by, s, s, 0xC0C0C0);
                    // 1-px inset border
                    for (int k = 0; k < s; k++) {
                        put_pixel_back(bx + k, by, 0x808080);
                        put_pixel_back(bx, by + k, 0x808080);
                    }
                    if (c.mine) {
                        draw_rect_filled(bx + s/2 - 3, by + s/2 - 3, 6, 6, TEXT_BLACK);
                    } else if (c.adj > 0) {
                        static const uint32_t NUMC[9] = {
                            0, 0x0000C0, 0x008000, 0xC00000, 0x000080,
                            0x800000, 0x008080, 0x000000, 0x808080
                        };
                        char b[2] = { (char)('0' + c.adj), 0 };
                        draw_string_centered(b, bx, by, s, s, NUMC[c.adj]);
                    }
                } else {
                    draw_button(bx, by, s, s, false, 0xC0C0C0);
                    if (c.flagged) {
                        draw_rect_filled(bx + s/3, by + 4, s/4, s - 8, TEXT_BLACK);
                        draw_rect_filled(bx + s/3 + s/4, by + 4, s/3, s/3, BUTTON_CLOSE);
                    }
                }
            }
        }

        // Flag-mode indicator
        if (flag_mode_) {
            const char* m = "[F]";
            draw_string(m, cx + 6, cy + ch - 12, BUTTON_CLOSE);
        }
    }

    void on_click(int rx, int ry) override {
        int ax = x + rx;
        int ay = y + APP_TITLEBAR_H + ry;

        // Reset button?
        if (ax >= reset_btn_x_ && ax < reset_btn_x_ + reset_btn_s_
            && ay >= reset_btn_y_ && ay < reset_btn_y_ + reset_btn_s_) {
            new_game(); return;
        }

        // Board cell?
        if (cell_s_ > 0 && ax >= board_x_ && ax < board_x_ + GW * cell_s_
            && ay >= board_y_ && ay < board_y_ + GH * cell_s_) {
            int ci = (ax - board_x_) / cell_s_;
            int cj = (ay - board_y_) / cell_s_;
            if (flag_mode_) toggle_flag(ci, cj);
            else            reveal(ci, cj);
        }
    }

    void on_mouse_right_click(int mx, int my) override {
        if (cell_s_ <= 0) return;
        if (mx >= board_x_ && mx < board_x_ + GW * cell_s_
            && my >= board_y_ && my < board_y_ + GH * cell_s_) {
            int ci = (mx - board_x_) / cell_s_;
            int cj = (my - board_y_) / cell_s_;
            toggle_flag(ci, cj);
        }
    }

    void on_key_press(char c) override {
        if (c == 'n' || c == 'N') new_game();
        else if (c == 'f' || c == 'F') flag_mode_ = !flag_mode_;
    }

private:
    static constexpr int GW = 10;
    static constexpr int GH = 10;
    static constexpr int NUM_MINES = 15;
    enum State { PLAY, WIN, LOSE };

    struct Cell { bool mine; bool revealed; bool flagged; int8_t adj; };
    Cell cells_[GW * GH];
    State state_;
    bool flag_mode_;
    bool started_;
    int  tick_, elapsed_;
    uint32_t rng_;

    int board_x_ = 0, board_y_ = 0, cell_s_ = 0;
    int reset_btn_x_ = 0, reset_btn_y_ = 0, reset_btn_s_ = 0;

    uint32_t rand() { rng_ = rng_ * 1103515245u + 12345u; return rng_; }

    int mines_left() const {
        int flagged = 0;
        for (int i = 0; i < GW * GH; i++) if (cells_[i].flagged) flagged++;
        int left = NUM_MINES - flagged;
        return left < 0 ? 0 : left;
    }

    void new_game() {
        for (int i = 0; i < GW * GH; i++) cells_[i] = {false, false, false, 0};
        int placed = 0;
        while (placed < NUM_MINES) {
            int idx = rand() % (GW * GH);
            if (!cells_[idx].mine) { cells_[idx].mine = true; placed++; }
        }
        for (int j = 0; j < GH; j++) {
            for (int i = 0; i < GW; i++) {
                if (cells_[j * GW + i].mine) continue;
                int8_t n = 0;
                for (int dj = -1; dj <= 1; dj++) for (int di = -1; di <= 1; di++) {
                    int ni = i + di, nj = j + dj;
                    if (ni < 0 || ni >= GW || nj < 0 || nj >= GH) continue;
                    if (cells_[nj * GW + ni].mine) n++;
                }
                cells_[j * GW + i].adj = n;
            }
        }
        state_ = PLAY; started_ = false;
        tick_ = 0; elapsed_ = 0;
    }

    void toggle_flag(int i, int j) {
        if (state_ != PLAY) return;
        Cell& c = cells_[j * GW + i];
        if (c.revealed) return;
        c.flagged = !c.flagged;
    }

    void reveal(int i, int j) {
        if (state_ != PLAY) return;
        Cell& c = cells_[j * GW + i];
        if (c.revealed || c.flagged) return;
        started_ = true;
        c.revealed = true;
        if (c.mine) { state_ = LOSE; reveal_all_mines(); return; }
        if (c.adj == 0) {
            for (int dj = -1; dj <= 1; dj++) for (int di = -1; di <= 1; di++) {
                if (di == 0 && dj == 0) continue;
                int ni = i + di, nj = j + dj;
                if (ni < 0 || ni >= GW || nj < 0 || nj >= GH) continue;
                if (!cells_[nj * GW + ni].revealed) reveal(ni, nj);
            }
        }
        check_win();
    }

    void reveal_all_mines() {
        for (int i = 0; i < GW * GH; i++) if (cells_[i].mine) cells_[i].revealed = true;
    }

    void check_win() {
        for (int i = 0; i < GW * GH; i++) {
            if (!cells_[i].mine && !cells_[i].revealed) return;
        }
        state_ = WIN;
    }
};

#endif
