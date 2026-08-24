#pragma once
// 10_window_manager_impl.h
// Out-of-class WindowManager method bodies (context menu actions,
// input routing/focus handling, etc.) that need the complete
// TerminalWindow/FileExplorerWindow types, plus a few small bridging
// functions and swap_buffers().
// Extracted from kernel.cpp (original lines 8922-9359) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.


// NpaPrint adapter — forwards into a TerminalWindow*. Forward-declared
// above so the matrix command handler can take its address before
// TerminalWindow is complete; defined here now that the type is whole.
void npa_term_print(void* ctx, const char* s) {
    static_cast<TerminalWindow*>(ctx)->console_print(s);
}

// TestSink::put_line implementation. Defined here because it needs the
// complete TerminalWindow type to route text into the window that owns
// the test overlay. Falls back silently if no terminal owns it.
extern "C" void test_sink_put_line(const char* s) {
    if (!s) return;
    if (g_test_overlay_owner) {
        ((TerminalWindow*)g_test_overlay_owner)->console_print(s);
    }
}

void WindowManager::execute_context_menu_action(int item_index) {
    if (item_index < 0 || item_index >= num_context_menu_items) return;
    const char* action = context_menu_items[item_index];

    if (current_context == CTX_DESKTOP) {
        if (strcmp(action, "File Explorer") == 0) {
            launch_new_explorer();
        } else if (strcmp(action, "Paste") == 0) {
            if (g_clipboard_buffer[0] != '\0') {
                const char* src_path = g_clipboard_buffer;
                const char* filename = strrchr(src_path, '/');
                filename = filename ? filename + 1 : src_path;
                
                char new_name[32] = "copy_of_";
                strncat(new_name, filename, 22);

                fat32_copy_file(src_path, new_name);
                load_desktop_items();
            }
        }
    }
    else if (current_context == CTX_ICON) {
        DesktopItem& item = desktop_items[context_icon_idx];
        
        if (strcmp(action, "Run") == 0) {
            // Same fix as the explorer's Run action: "run <file>" isn't a
            // recognized shell command, "bochs <file>" is.
            char command_buffer[128];
            snprintf(command_buffer, 128, "bochs %s", item.name);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Edit") == 0) {
            char command_buffer[128];
            snprintf(command_buffer, 128, "edit \"%s\"", item.name);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Copy") == 0) {
            strncpy(g_clipboard_buffer, item.path, 1023);
        } else if (strcmp(action, "Delete") == 0) {
            fat32_remove_file(item.path);
            load_desktop_items();
        }
    }
    else if (current_context == CTX_EXPLORER_ITEM) {
        const char* filename = context_file_path;
        bool needs_explorer_refresh = false;

        if (strcmp(action, "Run") == 0) {
            // "run <file>" is not a recognized shell command (see
            // handle_command()'s dispatch table) -- "bochs <file>" is the
            // actual ELF-execution entry point. Using "run" here silently
            // did nothing.
            char command_buffer[128];
            snprintf(command_buffer, 128, "bochs %s", filename);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Edit") == 0) {
            char command_buffer[128];
            snprintf(command_buffer, 128, "edit \"%s\"", filename);
            launch_terminal_with_command(command_buffer);
        } else if (strcmp(action, "Create Shortcut") == 0) {
            char shortcut_name[32];
            char shortcut_content[128];
            
            strncpy(shortcut_name, filename, 27);
            char* dot = strrchr(shortcut_name, '.');
            if (dot) *dot = '\0';
            strcat(shortcut_name, ".lnk");

            snprintf(shortcut_content, 128, "run %s", filename);

            fat32_write_file(shortcut_name, shortcut_content, strlen(shortcut_content));
            load_desktop_items();
            needs_explorer_refresh = true;
        } else if (strcmp(action, "Copy") == 0) {
            // Previously unimplemented: "Copy" appeared in the menu but did
            // nothing when clicked. Store the file path in the shared
            // clipboard buffer, same as desktop-icon Copy does.
            strncpy(g_clipboard_buffer, filename, 1023);
            g_clipboard_buffer[1023] = '\0';
        } else if (strcmp(action, "Delete") == 0) {
            // Previously unimplemented: "Delete" appeared in the menu but
            // did nothing when clicked.
            fat32_remove_file(filename);
            load_desktop_items();
            needs_explorer_refresh = true;
        }

        // The explorer window was necessarily focused for its context menu
        // to have opened (see handle_input's right-click routing), so
        // refresh whatever window is currently focused.
        if (needs_explorer_refresh && focused_idx >= 0 && focused_idx < num_windows) {
            windows[focused_idx]->refresh_contents();
        }
    }

    context_menu_active = false;
}

void WindowManager::handle_input(char key, int mx, int my, bool left_down, bool left_clicked, bool right_clicked) {
    // --- Static variables to track double-clicks ---
    static uint32_t last_click_tick = 0;
    static int last_click_icon_idx = -1;
    const uint32_t DOUBLE_CLICK_SPEED = 20; // Ticks to wait for a double click

    // --- 1. Handle Context Menu Clicks ---
    if (context_menu_active && left_clicked) {
        int menu_width = 150;
        int item_height = 20;
        if (mx > context_menu_x && mx < context_menu_x + menu_width) {
            int item_index = (my - context_menu_y) / item_height;
            if (item_index >= 0 && item_index < num_context_menu_items) {
                execute_context_menu_action(item_index);
                return; // Action taken, end input handling
            }
        }
        context_menu_active = false; // Clicked outside, close menu
    }

    if (context_menu_active && right_clicked) {
        context_menu_active = false;
        return;
    }

    // --- 1.5. Handle Corner-Drag Resizing ---
    if (resizing_idx != -1) {
        if (left_down) {
            Window* rw = windows[resizing_idx];
            int new_w = resize_orig_w + (mx - resize_start_mx);
            int new_h = resize_orig_h + (my - resize_start_my);
            int minw = rw->min_w(), minh = rw->min_h();
            if (new_w < minw) new_w = minw;
            if (new_h < minh) new_h = minh;
            // Keep the window from growing past the visible screen (and
            // out from under the taskbar) — same bound draw_desktop()
            // uses for the taskbar's own height.
            int maxw = (int)fb_info.width - rw->x;
            int maxh = ((int)fb_info.height - 40) - rw->y;
            if (maxw < minw) maxw = minw;
            if (maxh < minh) maxh = minh;
            if (new_w > maxw) new_w = maxw;
            if (new_h > maxh) new_h = maxh;
            rw->w = new_w;
            rw->h = new_h;
        } else {
            resizing_idx = -1;
        }
        return;
    }

    // --- 2. Handle Dragging ---
    if (dragging_idx != -1) { // Dragging a window
        if (left_down) {
            windows[dragging_idx]->x = mx - drag_offset_x;
            windows[dragging_idx]->y = my - drag_offset_y;
        } else {
            dragging_idx = -1;
        }
        return;
    }
    if (dragging_icon_idx != -1) { // Dragging an icon
        if (left_down) {
            desktop_items[dragging_icon_idx].x = mx - drag_offset_x;
            desktop_items[dragging_icon_idx].y = my - drag_offset_y;
        } else {
            dragging_icon_idx = -1;
        }
        return;
    }
    
    // --- 3. Handle Right Clicks (Opening Context Menu) ---
    if (right_clicked) {
		// Check window interactions first (top to bottom), same as left
		// click below. Previously this only ever checked the window that
		// was ALREADY focused — right-clicking a background window (one
		// not already in focus) fell straight through to the desktop-icon
		// checks below and either did nothing or opened the desktop's
		// context menu instead of that window's. Now a right-click on any
		// window focuses it and dispatches the click to it, matching how
		// left-click already behaves.
		for (int i = num_windows - 1; i >= 0; i--) {
			if (windows[i]->is_minimized) continue; // hidden — no on-screen hit area
			if (mx >= windows[i]->x && mx < windows[i]->x + windows[i]->w &&
				my >= windows[i]->y && my < windows[i]->y + windows[i]->h) {
				// Capture the target BEFORE set_focus(), which reshuffles
				// windows[] (moves the focused window to the end and
				// shifts everything after idx down by one) — using
				// windows[i] afterward would operate on whatever window
				// slid into slot i, not the one actually clicked.
				Window* target = windows[i];
				set_focus(i);
				target->on_mouse_right_click(mx, my);
				return; // The window handled the click
			}
		}
        // First, check if a click happened on a desktop icon
        int clicked_icon_index = -1;
        for (int i = num_desktop_items - 1; i >= 0; --i) {
            if (mx >= desktop_items[i].x && mx < desktop_items[i].x + 40 &&
                my >= desktop_items[i].y && my < desktop_items[i].y + 50) {
                clicked_icon_index = i; // Save the index of the clicked icon
                break; // Found it, no need to check others
            }
        }

        if (clicked_icon_index != -1) {
            // A desktop icon was right-clicked
            context_menu_active = true;
            context_menu_x = mx;
            context_menu_y = my;
            current_context = CTX_ICON;
            context_icon_idx = clicked_icon_index; // Use the saved index
            num_context_menu_items = 0;

            // Check if it's an executable
            if (strstr(desktop_items[clicked_icon_index].name, ".obj") != nullptr || strstr(desktop_items[clicked_icon_index].name, ".OBJ") != nullptr) {
                context_menu_items[num_context_menu_items++] = "Run";
            }
            
            context_menu_items[num_context_menu_items++] = "Edit"; // ADDED THIS LINE
            context_menu_items[num_context_menu_items++] = "Copy";
            context_menu_items[num_context_menu_items++] = "Delete";

        } else {
            // No icon was clicked, this is a right-click on the desktop itself
            context_menu_active = true;
            context_menu_x = mx;
            context_menu_y = my;
            current_context = CTX_DESKTOP;
            num_context_menu_items = 0;
            context_menu_items[num_context_menu_items++] = "File Explorer";
            context_menu_items[num_context_menu_items++] = "Paste";
        }
        return;
    }

    // --- 4. Handle Left Clicks (Dragging, Opening, Focusing) ---
    if (left_clicked) {
        // Check window interactions first (top to bottom)
        for (int i = num_windows - 1; i >= 0; i--) {
            if (windows[i]->is_minimized) continue; // hidden — no on-screen hit area
            if (mx >= windows[i]->x && mx < windows[i]->x + windows[i]->w &&
                my >= windows[i]->y && my < windows[i]->y + windows[i]->h) {
                
                // Capture the target BEFORE set_focus(), which reshuffles
                // windows[] (moves the focused window to the end and
                // shifts everything after idx down by one) — using
                // windows[i] afterward would operate on whatever window
                // slid into slot i, not the one actually clicked (e.g.
                // clicking a background window's close button could close
                // a completely different window).
                Window* target = windows[i];
                set_focus(i);
                if (target->is_in_close_button(mx, my)) {
                    target->close();
                } else if (target->get_taskbar_id() >= 0 && target->is_in_minimize_button(mx, my)) {
                    // Minimize button is only drawn for terminal windows
                    // (get_taskbar_id() >= 0); other window types don't
                    // render one, so don't treat that screen area as a
                    // hidden hotspot for them.
                    target->is_minimized = true;
                } else if (target->get_taskbar_id() >= 0 && target->is_in_resize_grip(mx, my)) {
                    // Resize grip is only drawn for (and, for now, only
                    // active on) terminal windows — see draw_resize_grip()
                    // in TerminalWindow::draw(). Same get_taskbar_id() >= 0
                    // gate the minimize button above uses, since the other
                    // desktop-suite mini-apps (calculator, snake, etc.)
                    // draw fixed layouts that weren't built to relayout at
                    // arbitrary sizes.
                    resizing_idx = focused_idx;
                    resize_start_mx = mx;
                    resize_start_my = my;
                    resize_orig_w = target->w;
                    resize_orig_h = target->h;
                } else if (target->is_in_titlebar(mx, my)) {
                    dragging_idx = focused_idx;
                    drag_offset_x = mx - target->x;
                    drag_offset_y = my - target->y;
                } else {
                    target->on_mouse_click(mx, my);
                }
                return;
            }
        }

        // Check icon interactions (double-click and drag start)
        for (int i = num_desktop_items - 1; i >= 0; --i) {
            if (mx >= desktop_items[i].x && mx < desktop_items[i].x + 32 &&
                my >= desktop_items[i].y && my < desktop_items[i].y + 45) {

                // Check for a double-click
                if (last_click_icon_idx == i && (g_timer_ticks - last_click_tick) < DOUBLE_CLICK_SPEED) {
                    // Double-click detected!
                    DesktopItem& item = desktop_items[i]; // Use a reference for cleaner code

					if (strcmp(item.path, "explorer.app") == 0) {
						launch_new_explorer();
					} 
					// This part handles executing .obj files
					else if (strstr(item.name, ".obj") != nullptr || strstr(item.name, ".OBJ") != nullptr) {
						// Same fix as the explorer's Run action: "run <file>"
						// isn't a recognized shell command.
						char command_buffer[128];
						snprintf(command_buffer, 128, "bochs %s", item.name);
						launch_terminal_with_command(command_buffer);
					}
                    
                    // Reset double-click tracking
                    last_click_tick = 0;
                    last_click_icon_idx = -1;
                } else {
                    // This is a first click, start dragging and set up for double-click
                    dragging_icon_idx = i;
                    drag_offset_x = mx - desktop_items[i].x;
                    drag_offset_y = my - desktop_items[i].y;
                    last_click_icon_idx = i;
                    last_click_tick = g_timer_ticks;
                }
                return;
            }
        }

        // Check taskbar button clicks — layout mirrors draw_desktop()
        if (my >= (int)fb_info.height - 36 && my <= (int)fb_info.height - 4) {
            int btn_w = 80;
            int bx = 4;
            // "Terminal" launcher
            if (mx >= bx && mx < bx + btn_w) {
                launch_new_terminal();
                return;
            }
            bx += btn_w + 4;

            // Per-terminal-window buttons, walked in the same stable
            // get_taskbar_id() order draw_desktop() uses (windows[] itself
            // gets reshuffled by set_focus(), so array order isn't stable).
            // A single click here both raises/focuses the window AND — if
            // it was minimized — restores ("maximises") it back onto the
            // desktop in that same click.
            bool shown[16] = { false };
            for (int shown_count = 0; shown_count < num_windows; ++shown_count) {
                int best_i = -1, best_id = 0x7fffffff;
                for (int i = 0; i < num_windows; ++i) {
                    if (shown[i]) continue;
                    int tid = windows[i]->get_taskbar_id();
                    if (tid < 0) { shown[i] = true; continue; } // not a terminal window
                    if (tid < best_id) { best_id = tid; best_i = i; }
                }
                if (best_i < 0) break; // nothing left to show
                shown[best_i] = true;

                if (mx >= bx && mx < bx + btn_w) {
                    windows[best_i]->is_minimized = false;
                    set_focus(best_i);
                    return;
                }
                bx += btn_w + 4;
                if (bx + btn_w >= (int)fb_info.width - 100) break;
            }
        }

        // If nothing was clicked, reset double-click tracking
        last_click_icon_idx = -1;
    }

    // --- 5. Handle Keyboard Input ---
    if (key != 0 && focused_idx != -1 && focused_idx < num_windows)
        windows[focused_idx]->on_key_press(key);
}

void WindowManager::print_to_focused(const char* s) {
    if (focused_idx != -1 && focused_idx < num_windows) 
        windows[focused_idx]->console_print(s);
}

void launch_new_terminal() {
    static int win_count = 0;
    int idx = (win_count++ % 10);
    int off = idx * 30;
    wm.add_window(new TerminalWindow(100 + off, 50 + off));
}


void launch_new_explorer() {
    static int win_count = 0;
    int idx = (win_count++ % 10);
    int off = idx * 30;
    wm.add_window(new FileExplorerWindow(120 + off, 70 + off, "/"));
}


// ADD THIS NEW FUNCTION
void launch_terminal_with_command(const char* command) {
    static int win_count = 0;
    int idx = (win_count++ % 10);
    int off = idx * 30;
    wm.add_window(new TerminalWindow(150 + off, 90 + off, command));
}

void swap_buffers() {
    // Safety: never blit to VGA text region or below 16MB physical
    if (!fb_info.ptr || !backbuffer) return;
    if ((uintptr_t)fb_info.ptr < 0x1000000u) return;
    uint32_t pitch_pixels = fb_info.pitch / 4;  // pitch is in bytes, convert to pixels
    if (pitch_pixels == fb_info.width) {
        // Fast path: pitch matches width, single blit
        uint32_t* dest = fb_info.ptr;
        uint32_t* src = backbuffer;
        size_t count = fb_info.width * fb_info.height;
        asm volatile (
            "rep movsl"
            : "=S"(src), "=D"(dest), "=c"(count)
            : "S"(src), "D"(dest), "c"(count)
            : "memory"
        );
    } else {
        // Pitch != width: copy row by row respecting stride
        for (uint32_t y = 0; y < fb_info.height; y++) {
            uint32_t* dest = (uint32_t*)((uint8_t*)fb_info.ptr + y * fb_info.pitch);
            uint32_t* src  = backbuffer + y * fb_info.width;
            uint32_t  count = fb_info.width;
            asm volatile (
                "rep movsl"
                : "=S"(src), "=D"(dest), "=c"(count)
                : "S"(src), "D"(dest), "c"(count)
                : "memory"
            );
        }
    }
}

// TestSink::flush implementation. test_module_run() blocks the kernel
// main loop for the entire duration of a test, so the normal per-frame
// wm.update_all() + swap_buffers() pass never gets to run. The module
// calls this between breadcrumbs and around blocking calls so the
// overlay is painted and pushed to the screen live — and so a hang
// inside the Bochs glue still leaves a frame on screen showing exactly
// how far the test got. It mirrors the main loop's paint sequence.
extern "C" void test_sink_flush(void) {
    g_gfx.clear_screen(ColorPalette::DESKTOP_GRAY );
    wm.update_all();                       // draws windows incl. overlay
    draw_cursor(mouse_x, mouse_y, ColorPalette::CURSOR_WHITE);
    draw_vga_overlay();                    // framebuffer breadcrumb rows
    swap_buffers();                        // push frame to the display
}

static volatile bool g_evt_timer = false;
static volatile bool g_evt_input = false;
static volatile bool g_evt_dirty = true;
// This is now defined before TerminalWindow to resolve the dependency
// static volatile uint32_t g_timer_ticks = 0;

extern "C" void idle_signal_timer() { g_evt_timer = true; g_timer_ticks++; }
extern "C" void idle_signal_input() { g_evt_input = true; }
extern "C" void mark_screen_dirty() { g_evt_dirty = true; }

static void init_screen_timer(uint16_t hz) {
    uint16_t divisor = 1193182 / hz;
    outb(0x43, 0x36);
    outb(0x40, divisor & 0xFF);
    outb(0x40, (divisor >> 8) & 0xFF);
}
