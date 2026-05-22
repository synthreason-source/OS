// =====================================================================
// desktop_suite/launcher.h — single entry point for opening apps
// =====================================================================
//
// One include pulls in every app and exposes a name-keyed launcher so
// terminal commands and start-menu entries share one dispatch table.
//
// Usage from kernel.cpp:
//   #include "desktop_suite/launcher.h"
//   ...
//   desktop_launch("calc",  &wm);
//   desktop_launch("paint", &wm);
//
// Returns true if launched, false if unknown name.

#ifndef DESKTOP_LAUNCHER_H
#define DESKTOP_LAUNCHER_H

#include "apps/about_window.h"
#include "apps/calculator_window.h"
#include "apps/clock_window.h"
#include "apps/matrix_inspector_window.h"
#include "apps/minesweeper_window.h"
#include "apps/paint_window.h"
#include "apps/snake_window.h"
#include "apps/system_monitor_window.h"

// Small helper for case-insensitive name match.
static inline bool dlauncher_match(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = ca - 'A' + 'a';
        if (cb >= 'A' && cb <= 'Z') cb = cb - 'A' + 'a';
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

// Spawn the named app. Aliases are listed in the if-chain for
// discoverability — "monitor" and "sysmon" both open System Monitor,
// etc.  Returns true on success.
static inline bool desktop_launch(const char* name, WindowManager* wm,
                                  int x = -1, int y = -1) {
    if (!name || !*name || !wm) return false;
    // Cascade so multiple windows don't overlap perfectly.
    static int cascade = 0;
    int ox = (cascade % 6) * 24;
    int oy = (cascade % 6) * 24;
    cascade++;
    int sx = x < 0 ? 80  + ox : x;
    int sy = y < 0 ? 60  + oy : y;

    if (dlauncher_match(name, "clock"))         { wm->add_window(new ClockWindow(sx, sy));            return true; }
    if (dlauncher_match(name, "calc")
     || dlauncher_match(name, "calculator"))    { wm->add_window(new CalculatorWindow(sx, sy));       return true; }
    if (dlauncher_match(name, "paint"))         { wm->add_window(new PaintWindow(sx, sy));            return true; }
    if (dlauncher_match(name, "snake"))         { wm->add_window(new SnakeWindow(sx, sy));            return true; }
    if (dlauncher_match(name, "mines")
     || dlauncher_match(name, "minesweeper"))   { wm->add_window(new MinesweeperWindow(sx, sy));      return true; }
    if (dlauncher_match(name, "monitor")
     || dlauncher_match(name, "sysmon")
     || dlauncher_match(name, "top"))           { wm->add_window(new SystemMonitorWindow(sx, sy));    return true; }
    if (dlauncher_match(name, "matrix")
     || dlauncher_match(name, "inspector"))     { wm->add_window(new MatrixInspectorWindow(sx, sy));  return true; }
    if (dlauncher_match(name, "about"))         { wm->add_window(new AboutWindow(sx, sy));            return true; }
    return false;
}

// Names exposed for help text + start menus. NULL-terminated.
static inline const char** desktop_app_names() {
    static const char* NAMES[] = {
        "clock", "calc", "paint", "snake", "mines",
        "monitor", "matrix", "about", nullptr,
    };
    return NAMES;
}

#endif
