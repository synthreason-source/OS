// =====================================================================
// desktop_suite/commands_patch.cpp — paste into handle_command()
// =====================================================================
//
// Sits next to the matrix/recurse/hello/about handlers from the earlier
// patch set. Adds terminal commands to launch each new GUI app.
//
// IMPORTANT: if you've already applied the earlier `about` command
// (which printed a text banner), REPLACE that handler with the one
// below — same name, but it now opens the AboutWindow dialog instead.

// Near the top of kernel.cpp (alongside `#include "matrix_array.h"`):
#include "desktop_suite/launcher.h"

// ---------- inside handle_command(), before the fall-through `else {` ----------

else if (strcmp(command, "launch") == 0 || strcmp(command, "open") == 0) {
    char* app = get_arg(args, 0);
    if (!app) {
        console_print("Usage: launch <app>\n");
        console_print("Apps:");
        for (const char** n = desktop_app_names(); *n; ++n) {
            console_print(" "); console_print(*n);
        }
        console_print("\n");
        return;
    }
    if (!desktop_launch(app, &wm)) {
        console_print("launch: unknown app '"); console_print(app); console_print("'\n");
    }
}
else if (strcmp(command, "clock")     == 0) { desktop_launch("clock",   &wm); }
else if (strcmp(command, "calc")      == 0
      || strcmp(command, "calculator")== 0) { desktop_launch("calc",    &wm); }
else if (strcmp(command, "paint")     == 0) { desktop_launch("paint",   &wm); }
else if (strcmp(command, "snake")     == 0) { desktop_launch("snake",   &wm); }
else if (strcmp(command, "mines")     == 0
      || strcmp(command, "minesweeper")==0) { desktop_launch("mines",   &wm); }
else if (strcmp(command, "monitor")   == 0
      || strcmp(command, "sysmon")    == 0
      || strcmp(command, "top")       == 0) { desktop_launch("monitor", &wm); }
else if (strcmp(command, "inspector") == 0) { desktop_launch("matrix",  &wm); }
// NOTE: REPLACE the earlier text-print `about` handler with this — same name,
// now opens the AboutWindow dialog (the BaseAppWindow version).
else if (strcmp(command, "about")     == 0) { desktop_launch("about",   &wm); }
