/* gfx_demo.c — minimal demo of the graphics ABI added to
 * bochs_drivers.h. Compiles like any other guest program:
 *
 *   make cc SRC=gfx_demo.c
 *
 * Then, inside the OS shell:
 *
 *   gfx_demo
 *
 * It fills the terminal window with a scrolling plaid/gradient pattern
 * for a few hundred frames, then exits back to the shell. Press any
 * key to quit early.
 */
#include "bochs_drivers.h"

void _start(void)
{
    int t = 0;

    for (int frame = 0; frame < 600; frame++) {
        /* Bail out early if the user typed anything. */
        /* (non-blocking: inb returns 0 if nothing queued) */
        if (inb(0xE7) != 0) break;

        for (int y = 0; y < GFX_HEIGHT; y++) {
            for (int x = 0; x < GFX_WIDTH; x++) {
                unsigned char r = (unsigned char)((x * 2 + t) & 0xFF);
                unsigned char g = (unsigned char)((y * 2 + t / 2) & 0xFF);
                unsigned char b = (unsigned char)(((x + y) + t) & 0xFF);
                gfx_set_pixel(x, y, ((unsigned int)r << 16) |
                                     ((unsigned int)g << 8)  |
                                      (unsigned int)b);
            }
        }
        gfx_present();
        t += 4;
    }

    gfx_exit();       /* back to plain text mode */
    kputs("gfx_demo finished.\n");
    kexit(0);
}
