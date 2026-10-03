/* gui_demo_static.c -- same UI as gui_demo.c, but declared as DATA.
 * Variables: 0=click count, 1=scrollbar value.  Textbox slot 0.
 * The ELF carries .guiscene; the kernel renders it. */
#include "gui_scene.h"

GUI_SCENE(
    GUI_HEADER(320, 200, 0x202428),
    GUI_INITVAR(1, 50),
    GUI_BUTTON(10, 10, 90, 22, "Click me", GUI_ACT_ADD, 0, 1),
    GUI_SCROLL(280, 10, 14, 160, 1, 0, 100),
    GUI_BARV(200, 10, 16, 160, 0xFFB000, 1, 0, 100),
    GUI_TEXTBOX(10, 50, 200, 18, 0),
    GUI_TEXT(10, 80, 0x9A9A9A, "Clicks:"),
    GUI_VALUE(70, 80, 0xE0E0E0, 0),
    GUI_TEXT(10, 100, 0x9A9A9A, "Press Quit to exit."),
    GUI_BUTTON(10, 120, 60, 20, "Quit", GUI_ACT_QUIT, 0, 0)
);

/* Nothing to execute: kept only so the file links as a normal guest. */
void _start(void) { for (;;) { } }
