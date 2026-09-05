/* driverkit.c — a small GUI "driver kit": one panel per hardware
 * service exposed by drivers.h (console, keyboard, mouse, disk,
 * graphics), each with a "Test" button and a live pass/fail status
 * line. All the actual test logic lives in driver.h; this file is
 * just comp.h widgets wired up to it.
 *
 * Build (from the host):
 *     make cc SRC=driverkit.c
 * Or from the OS shell:
 *     cc driverkit.c
 *     driverkit
 *
 * Layout
 * ------
 *   - Four rows (Console / Keyboard / Mouse / Disk), each: name,
 *     a "Test" button, and that driver's last result + message.
 *     Keyboard and mouse also update live every frame just from
 *     polling, independent of their button -- the button re-runs
 *     drv_console_test()/drv_disk_test() to force a fresh explicit
 *     test, matching what "Test" means for a one-shot driver.
 *   - A graphics test panel: "Test" toggles a live color-bar/gradient
 *     pattern on and off inside its own canvas rectangle, drawn fresh
 *     every frame via drv_graphics_test() so it's visibly live rather
 *     than a static snapshot.
 *   - A "Run All" button at the top re-runs every one-shot test
 *     (console + disk; keyboard/mouse/graphics are already live or
 *     toggle-based) in one click.
 *
 * Design notes
 * ------------
 *   - No libc, no malloc -- same style as editf.c and driver.h.
 *   - Colors: PASS is green text, FAIL is red, "not run yet" / "no
 *     signal" is the dim gray comp.h already uses for secondary text.
 */
#include "comp.h"
#include "driver.h"

void* memset(void* d, int v, unsigned long n) {
    unsigned char* dd = (unsigned char*)d;
    for (unsigned long i = 0; i < n; i++) dd[i] = (unsigned char)v;
    return d;
}

#define UI_COLOR_PASS 0x34C759
#define UI_COLOR_FAIL 0xFF3B30

static drv_status_t s_console;
static drv_status_t s_keyboard;
static drv_status_t s_mouse;
static drv_status_t s_disk;
static drv_status_t s_graphics;

static int s_gfx_test_on = 0;

/* ── layout ────────────────────────────────────────────────────────
 * Recomputed each frame from GFX_WIDTH/GFX_HEIGHT, same pattern as
 * editf.c's editor_layout(), so a resized window doesn't clip rows
 * that would otherwise assume a fixed canvas size. */
#define ROW_H     22
#define ROW_X     8
#define LIST_Y    32
#define NAME_W    76
#define BTN_W     56
#define BTN_H     18

static int s_gfx_box_x, s_gfx_box_y, s_gfx_box_w, s_gfx_box_h;

static void layout(void)
{
    s_gfx_box_x = ROW_X;
    s_gfx_box_y = LIST_Y + 4 * ROW_H + 24;
    s_gfx_box_w = GFX_WIDTH - 2 * ROW_X;
    if (s_gfx_box_w < 20) s_gfx_box_w = 20;
    s_gfx_box_h = GFX_HEIGHT - s_gfx_box_y - 20;
    if (s_gfx_box_h < 20) s_gfx_box_h = 20;
}

static unsigned int result_color(int result)
{
    if (result == 0) return UI_COLOR_PASS;
    if (result > 0)  return UI_COLOR_FAIL;
    return UI_COLOR_TEXT_DIM;
}

static void draw_row(ui_frame_t *f, int row, drv_status_t *st, int show_button, int *out_clicked)
{
    int y = LIST_Y + row * ROW_H;

    ui_draw_text(ROW_X, y + 5, st->name, UI_COLOR_TEXT);

    int clicked = 0;
    if (show_button) {
        ui_button_t btn = { ROW_X + NAME_W, y, BTN_W, BTN_H, "Test" };
        clicked = ui_button(f, &btn);
    }
    if (out_clicked) *out_clicked = clicked;

    int msg_x = ROW_X + NAME_W + (show_button ? BTN_W + 8 : 0);
    ui_draw_text(msg_x, y + 5, st->message, result_color(st->last_result));
}

void _start(void)
{
    kputs("driverkit: starting (console/keyboard/mouse/disk/graphics self-tests)...\n");

    drv_status_init(&s_console,   "Console");
    drv_status_init(&s_keyboard,  "Keyboard");
    drv_status_init(&s_mouse,     "Mouse");
    drv_status_init(&s_disk,      "Disk");
    drv_status_init(&s_graphics,  "Graphics");

    ui_button_t run_all_btn = { 0, 4, 90, 20, "Run All" };
    ui_button_t quit_btn;

    for (;;) {
        ui_frame_t f;
        ui_frame_begin(&f, UI_COLOR_BG);
        layout();

        run_all_btn.x = ROW_X;
        if (ui_button(&f, &run_all_btn)) {
            drv_console_test(&s_console);
            drv_disk_test(&s_disk);
        }

        quit_btn.x = GFX_WIDTH - 74; quit_btn.y = 4; quit_btn.w = 70; quit_btn.h = 20;
        quit_btn.label = "Quit";
        int quit_clicked = ui_button(&f, &quit_btn);

        /* Keyboard and mouse are continuously-live drivers -- poll
         * every frame regardless of any button, same cadence as
         * ordinary GUI input handling. */
        int key = 0;
        drv_keyboard_poll(&s_keyboard, &key);
        mouse_state_t ms;
        drv_mouse_poll(&s_mouse, &ms);

        int console_clicked = 0, disk_clicked = 0, gfx_clicked = 0;
        draw_row(&f, 0, &s_console,  1, &console_clicked);
        draw_row(&f, 1, &s_keyboard, 0, 0);
        draw_row(&f, 2, &s_mouse,    0, 0);
        draw_row(&f, 3, &s_disk,     1, &disk_clicked);

        if (console_clicked) drv_console_test(&s_console);
        if (disk_clicked)    drv_disk_test(&s_disk);

        /* Graphics row: the "Test" button here just toggles the live
         * pattern on/off (running the one-shot tests above via "Run
         * All" wouldn't make sense for a driver that's continuously
         * redrawn), so it gets its own row layout instead of
         * draw_row()'s generic one. */
        int gfx_y = LIST_Y + 4 * ROW_H;
        ui_draw_text(ROW_X, gfx_y + 5, s_graphics.name, UI_COLOR_TEXT);
        ui_button_t gfx_btn = { ROW_X + NAME_W, gfx_y, BTN_W, BTN_H,
                                 s_gfx_test_on ? "Stop" : "Test" };
        gfx_clicked = ui_button(&f, &gfx_btn);
        if (gfx_clicked) s_gfx_test_on = !s_gfx_test_on;

        if (s_gfx_test_on) {
            drv_graphics_test(&s_graphics, s_gfx_box_x, s_gfx_box_y, s_gfx_box_w, s_gfx_box_h);
        } else {
            ui_fill_rect(s_gfx_box_x, s_gfx_box_y, s_gfx_box_w, s_gfx_box_h, UI_COLOR_PANEL);
            ui_stroke_rect(s_gfx_box_x, s_gfx_box_y, s_gfx_box_w, s_gfx_box_h, UI_COLOR_BORDER);
            drv__strcpy(s_graphics.message, "Not running.", DRV_MSG_MAX);
            s_graphics.last_result = -1;
        }
        ui_draw_text(ROW_X + NAME_W + BTN_W + 8, gfx_y + 5, s_graphics.message,
                     result_color(s_graphics.last_result));

        ui_frame_end();

        if (quit_clicked) break;
    }

    gfx_exit();
    kputs("driverkit: exiting.\n");
    kexit(0);
}
