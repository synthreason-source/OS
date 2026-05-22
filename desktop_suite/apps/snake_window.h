// =====================================================================
// apps/snake_window.h — classic Snake
// =====================================================================
//
// Arrow keys to steer. Space to start/restart. Self-collision or wall =
// game over. Each pellet adds 1 to the score and grows the snake by 1.
//
// The snake is stored as a fixed-size ring buffer of cells: `head` is
// the index of the most recently advanced cell, `tail` of the oldest.
// This avoids per-tick allocations.

#ifndef DESKTOP_SNAKE_WINDOW_H
#define DESKTOP_SNAKE_WINDOW_H

#include "../base_window.h"

// Forward decl (defined in kernel.cpp)
#ifndef KEY_UP
#define KEY_UP    -1
#define KEY_DOWN  -2
#define KEY_LEFT  -3
#define KEY_RIGHT -4
#endif

class SnakeWindow : public BaseAppWindow {
public:
    SnakeWindow(int x, int y)
        : BaseAppWindow(x, y, 320, 290, "Snake"),
          tick_counter_(0), tick_period_(6),
          dir_dx_(1), dir_dy_(0), pending_dx_(1), pending_dy_(0),
          head_(0), tail_(0), len_(0),
          score_(0), game_over_(false), started_(false),
          rng_(1)
    {
        reset();
    }

    uint32_t bg_color() const override { return 0x202020; }

    void update() override {
        if (!started_ || game_over_) return;
        if (++tick_counter_ < tick_period_) return;
        tick_counter_ = 0;
        step();
    }

    void draw_content(int cx, int cy, int cw, int ch) override {
        using namespace ColorPalette;
        int board_x = cx + 8;
        int board_y = cy + 8;
        int board_w = cw - 16;
        int board_h = ch - 30;

        int scale_x = board_w / GW;
        int scale_y = board_h / GH;
        int s = scale_x < scale_y ? scale_x : scale_y;
        if (s < 4) s = 4;
        board_w = s * GW; board_h = s * GH;

        // Backdrop
        draw_rect_filled(board_x, board_y, board_w, board_h, 0x101010);
        // Grid lines (subtle)
        for (int i = 1; i < GW; i++)
            draw_rect_filled(board_x + i * s, board_y, 1, board_h, 0x202020);
        for (int j = 1; j < GH; j++)
            draw_rect_filled(board_x, board_y + j * s, board_w, 1, 0x202020);
        // Border
        for (int i = 0; i < board_w; i++) {
            put_pixel_back(board_x + i, board_y - 1,         TEXT_WHITE);
            put_pixel_back(board_x + i, board_y + board_h,   TEXT_WHITE);
        }
        for (int j = 0; j < board_h; j++) {
            put_pixel_back(board_x - 1,            board_y + j, TEXT_WHITE);
            put_pixel_back(board_x + board_w,      board_y + j, TEXT_WHITE);
        }

        // Snake
        int i = tail_;
        for (int k = 0; k < len_; k++) {
            int xx = ring_[i].x, yy = ring_[i].y;
            uint32_t c = (k == len_ - 1) ? 0x60FFA0 : 0x208840;
            draw_rect_filled(board_x + xx * s + 1, board_y + yy * s + 1,
                             s - 2, s - 2, c);
            i = (i + 1) % MAX_LEN;
        }
        // Pellet
        draw_rect_filled(board_x + pellet_x_ * s + 1,
                         board_y + pellet_y_ * s + 1,
                         s - 2, s - 2, 0xFF4040);

        // HUD
        char buf[24];
        const char* lbl = "score:";
        int n = 0; while (lbl[n]) { buf[n] = lbl[n]; n++; }
        buf[n++] = ' ';
        char sbuf[8]; int_to_string(score_, sbuf);
        int m = 0; while (sbuf[m]) { buf[n + m] = sbuf[m]; m++; }
        buf[n + m] = 0;
        draw_string(buf, board_x, board_y + board_h + 8, TEXT_WHITE);

        if (!started_) {
            draw_string_centered("[ space to start ]", cx, cy + 8 + board_h / 2,
                                 cw, 8, TEXT_GREEN);
        } else if (game_over_) {
            draw_rect_filled(cx + cw/2 - 90, cy + board_h/2 - 14, 180, 28, 0x000080);
            draw_string_centered("GAME OVER  — space to retry",
                                 cx + cw/2 - 90, cy + board_h/2 - 14,
                                 180, 28, TEXT_WHITE);
        }
    }

    void on_key_press(char c) override {
        if (c == ' ') {
            if (!started_ || game_over_) { reset(); started_ = true; }
            return;
        }
        if (c == KEY_UP    && dir_dy_ !=  1) { pending_dx_ =  0; pending_dy_ = -1; }
        if (c == KEY_DOWN  && dir_dy_ != -1) { pending_dx_ =  0; pending_dy_ =  1; }
        if (c == KEY_LEFT  && dir_dx_ !=  1) { pending_dx_ = -1; pending_dy_ =  0; }
        if (c == KEY_RIGHT && dir_dx_ != -1) { pending_dx_ =  1; pending_dy_ =  0; }
        // also WASD for systems where arrow scancodes don't pass through
        if ((c == 'w' || c == 'W') && dir_dy_ !=  1) { pending_dx_ =  0; pending_dy_ = -1; }
        if ((c == 's' || c == 'S') && dir_dy_ != -1) { pending_dx_ =  0; pending_dy_ =  1; }
        if ((c == 'a' || c == 'A') && dir_dx_ !=  1) { pending_dx_ = -1; pending_dy_ =  0; }
        if ((c == 'd' || c == 'D') && dir_dx_ != -1) { pending_dx_ =  1; pending_dy_ =  0; }
    }

private:
    static constexpr int GW = 24;
    static constexpr int GH = 16;
    static constexpr int MAX_LEN = GW * GH;
    struct Cell { int8_t x, y; };
    Cell ring_[MAX_LEN];
    int head_, tail_, len_;

    int tick_counter_, tick_period_;
    int dir_dx_, dir_dy_;
    int pending_dx_, pending_dy_;

    int pellet_x_, pellet_y_;
    int score_;
    bool game_over_, started_;

    uint32_t rng_;
    uint32_t rand() { rng_ = rng_ * 1103515245u + 12345u; return rng_; }

    void reset() {
        head_ = 2; tail_ = 0; len_ = 3;
        ring_[0] = {(int8_t)(GW/2 - 1), (int8_t)(GH/2)};
        ring_[1] = {(int8_t)(GW/2    ), (int8_t)(GH/2)};
        ring_[2] = {(int8_t)(GW/2 + 1), (int8_t)(GH/2)};
        dir_dx_ = pending_dx_ = 1;
        dir_dy_ = pending_dy_ = 0;
        score_ = 0;
        game_over_ = false;
        place_pellet();
    }

    void place_pellet() {
        for (int tries = 0; tries < 100; tries++) {
            int px = rand() % GW, py = rand() % GH;
            if (!cell_occupied(px, py)) { pellet_x_ = px; pellet_y_ = py; return; }
        }
        // fallback
        pellet_x_ = 0; pellet_y_ = 0;
    }

    bool cell_occupied(int px, int py) {
        int i = tail_;
        for (int k = 0; k < len_; k++) {
            if (ring_[i].x == px && ring_[i].y == py) return true;
            i = (i + 1) % MAX_LEN;
        }
        return false;
    }

    void step() {
        dir_dx_ = pending_dx_; dir_dy_ = pending_dy_;
        int nx = ring_[head_].x + dir_dx_;
        int ny = ring_[head_].y + dir_dy_;
        if (nx < 0 || nx >= GW || ny < 0 || ny >= GH) { game_over_ = true; return; }

        // Will we eat the pellet?
        bool eating = (nx == pellet_x_ && ny == pellet_y_);

        // Compute self-collision — eating skips tail-advance, so the tail
        // cell stays occupied this tick.
        int check_i = tail_;
        int check_n = eating ? len_ : (len_ - 1);  // ignore tail if it will move
        int start_i = eating ? tail_ : (tail_ + 1) % MAX_LEN;
        check_i = start_i;
        for (int k = 0; k < check_n; k++) {
            if (ring_[check_i].x == nx && ring_[check_i].y == ny) { game_over_ = true; return; }
            check_i = (check_i + 1) % MAX_LEN;
        }

        head_ = (head_ + 1) % MAX_LEN;
        ring_[head_] = {(int8_t)nx, (int8_t)ny};
        if (eating) {
            len_++;
            score_++;
            if (tick_period_ > 2 && (score_ % 5 == 0)) tick_period_--;
            place_pellet();
        } else {
            tail_ = (tail_ + 1) % MAX_LEN;
        }
    }
};

#endif
