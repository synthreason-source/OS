/* gfx_smoketest.c — smallest possible test of the graphics pipeline.
 * Fills the canvas solid blue with a direct array-write loop (no
 * per-pixel function calls), presents ONCE, prints a marker, then
 * just waits for a keypress. If this doesn't show a blue window, the
 * bug is in the present/blit path itself, not in how long the full
 * animated gfx_demo takes to compute a frame.
 *
 *   cc gfx_smoketest.c
 *   gfx_smoketest
 */
#include "bochs_drivers.h"

void _start(void)
{
    kputs("gfx_smoketest: filling...\n");

    for (int i = 0; i < GFX_WIDTH * GFX_HEIGHT; i++) {
        gfx_framebuffer[i] = 0x0000FF;   /* solid blue, 0x00RRGGBB */
    }

    kputs("gfx_smoketest: presenting...\n");
    gfx_present();

    /* This line only reaches the terminal once gfx_exit() below runs
     * and the window reverts to text mode -- it's queued, not lost,
     * so seeing it AFTER the window goes back to text confirms
     * gfx_present() returned control normally. */
    kputs("gfx_smoketest: presented, waiting for a key...\n");

    while (inb(0xE7) == 0) { /* spin until any key */ }

    gfx_exit();
    kputs("gfx_smoketest: done.\n");
    kexit(0);
}
