/* gui_demo.c — a tiny GUI to exercise compositor.h's widgets: a
 * button, a vertical scrollbar, and a text box, all driven by the
 * compositor's shared mouse cursor via bochs_drivers.h's mouse ABI.
 *
 * Build (from the host):
 *     make cc SRC=gui_demo.c
 * Or from the OS shell:
 *     cc gui_demo.c
 *     gui_demo
 *
 * Click the button to bump a counter, drag the scrollbar to change
 * the accent bar's height, click the text box and type to edit it.
 * Click outside the canvas (titlebar, another window, the desktop)
 * at any point and control simply goes back to the compositor, same
 * as clicking any other window — this program doesn't see it.
 */
#include "comp.h"

static ui_button_t    s_button    = { 10, 10, 90, 22, "Click me" };
static ui_scrollbar_t  s_scroll;
static ui_textbox_t    s_textbox;
static int             s_click_count = 0;

static void kput_int(int v)
{
    char buf[12];
    int n = 0;
    if (v < 0) { kputc('-'); v = -v; }
    if (v == 0) { kputc('0'); return; }
    while (v && n < 12) { buf[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n) kputc(buf[--n]);
}

void _start(void)
{
    kputs("gui_demo: starting (button + scrollbar + text box)...\n");

    ui_scrollbar_init(&s_scroll, 280, 10, 14, 160, 0, 100, 50);
    ui_textbox_init(&s_textbox, 10, 50, 200, 18);

    for (;;) {
        ui_frame_t f;
        ui_frame_begin(&f, UI_COLOR_BG);

        if (ui_button(&f, &s_button)) {
            s_click_count++;
        }

        //ui_scrollbar_update(&f, &s_scroll);
        //ui_scrollbar_draw(&s_scroll);

        /* Scrollbar drives the height of a simple accent bar, just to
         * make its value visible without needing a numeric readout. */
        //int bar_h = 2 + s_scroll.value * 140 / 100;
        //ui_fill_rect(200, 170 - bar_h, 16, bar_h, UI_COLOR_ACCENT);
        //ui_stroke_rect(200, 10, 16, 160, UI_COLOR_BORDER);

        ui_textbox_update(&f, &s_textbox);
        ui_textbox_draw(&s_textbox);

        ui_draw_text(10, 80, "Clicks:", UI_COLOR_TEXT_DIM);
        /* Draw the click counter directly onto the canvas, not via
         * kputc — this program owns the whole canvas while gfx mode
         * is active, and mixing text-mode output in would only show
         * up once gfx_exit() drops back to the scrolling console. */
        {
            char digits[12];
            int  n = 0, v = s_click_count;
            if (v == 0) { digits[n++] = '0'; }
            while (v && n < 12) { digits[n++] = (char)('0' + (v % 10)); v
/= 10; }
            char rev[13];
            for (int i = 0; i < n; i++) rev[i] = digits[n - 1 - i];
            rev[n] = 0;
            ui_draw_text(70, 80, rev, UI_COLOR_TEXT);
        }

        ui_draw_text(10, 100, "esc-less demo: click the button below to quit.", UI_COLOR_TEXT_DIM);
        ui_button_t quit_btn = { 10, 120, 60, 20, "Quit" };
        int should_quit = ui_button(&f, &quit_btn);

        ui_frame_end();

        if (should_quit) break;
    }

    gfx_exit();
    kputs("gui_demo: quit button pressed. Final click count: ");
    kput_int(s_click_count);
    kexit(0);
}
