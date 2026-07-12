#pragma once
// 04_window_system.h
// Desktop icon drawing, the base Window class, and WindowManager
// (declaration + inline members; out-of-class method bodies that need
// TerminalWindow/FileExplorerWindow live in 10_window_manager_impl.h).
// Extracted from kernel.cpp (original lines 1573-2019) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.


// =============================================================================
// WINDOW SYSTEM
// =============================================================================

// New: Icon drawing functions
void draw_icon_file(int x, int y, bool is_shortcut) {
    draw_rect_filled(x, y, 32, 32, ColorPalette::ICON_FILE_FILL);
    draw_rect_filled(x, y, 32, 1, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x + 31, y, 1, 32, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x, y + 31, 32, 1, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x, y, 1, 32, ColorPalette::ICON_FILE_OUTLINE);
    if(is_shortcut) {
        draw_rect_filled(x + 4, y + 22, 10, 6, ColorPalette::ICON_SHORTCUT_ARROW);
        put_pixel_back(x+8, y+20, ColorPalette::ICON_SHORTCUT_ARROW);
        put_pixel_back(x+9, y+21, ColorPalette::ICON_SHORTCUT_ARROW);
    }
}

void draw_icon_folder(int x, int y) {
    draw_rect_filled(x, y + 5, 32, 27, ColorPalette::ICON_FOLDER_FILL);
    draw_rect_filled(x, y, 14, 8, ColorPalette::ICON_FOLDER_FILL);
    draw_rect_filled(x, y + 31, 32, 1, ColorPalette::ICON_FILE_OUTLINE);
}

// Small (14x14) icon variants used by the File Explorer list view. The
// desktop icons above are 32x32, far taller than a compact list row —
// drawing them in a list caused each icon to spill into the rows above
// and below it (the "icon clipping" bug). These small variants are sized
// to fit exactly inside FileExplorerWindow::ROW_H so rows never overlap.
void draw_icon_file_small(int x, int y, bool is_shortcut) {
    draw_rect_filled(x, y, 14, 14, ColorPalette::ICON_FILE_FILL);
    draw_rect_filled(x, y, 14, 1, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x + 13, y, 1, 14, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x, y + 13, 14, 1, ColorPalette::ICON_FILE_OUTLINE);
    draw_rect_filled(x, y, 1, 14, ColorPalette::ICON_FILE_OUTLINE);
    if (is_shortcut) {
        draw_rect_filled(x + 2, y + 9, 5, 3, ColorPalette::ICON_SHORTCUT_ARROW);
        put_pixel_back(x + 4, y + 8, ColorPalette::ICON_SHORTCUT_ARROW);
    }
}

void draw_icon_folder_small(int x, int y) {
    draw_rect_filled(x, y + 3, 14, 11, ColorPalette::ICON_FOLDER_FILL);
    draw_rect_filled(x, y, 7, 3, ColorPalette::ICON_FOLDER_FILL);
    draw_rect_filled(x, y + 13, 14, 1, ColorPalette::ICON_FILE_OUTLINE);
}

// New: Desktop items structure
enum IconType { ICON_FILE, ICON_DIR, ICON_SHORTCUT, ICON_APP };
struct DesktopItem {
    char name[32];
    char path[128];
    int x, y;
    IconType type;
};

class Window {
public:
    int x, y, w, h;
    const char* title;
    bool has_focus;
    bool is_closed;
    // When true, the window is hidden (not drawn, not hit-tested) but
    // stays alive in the WindowManager's window list — i.e. it's still
    // "running", just tucked away. A taskbar button remains for it so a
    // single click there can bring it straight back (see
    // is_in_minimize_button() / WindowManager's taskbar click handling).
    bool is_minimized;

    Window(int x, int y, int w, int h, const char* title)
        : x(x), y(y), w(w), h(h), title(title), has_focus(false), is_closed(false),
          is_minimized(false) {}
    virtual ~Window() {}
    virtual void put_char(char c) {} // ADD THIS

    virtual void draw() = 0;
    virtual void on_key_press(char c) = 0;
    virtual void on_mouse_click(int mx, int my) {} // New
	virtual void on_mouse_right_click(int mx, int my) {} // ADD THIS LINE
	virtual void refresh_contents() {} // Lets WindowManager tell a window (e.g. FileExplorerWindow) to reload its data after a filesystem-mutating context-menu action.

    virtual void update() = 0;
    virtual void console_print(const char* s) {}
    virtual int  get_elf_slot() const { return -1; }  // overridden by TerminalWindow
    // Stable per-window ID used for taskbar buttons (overridden by
    // TerminalWindow). -1 means "doesn't get a taskbar button".
    virtual int  get_taskbar_id() const { return -1; }

    bool is_in_titlebar(int mx, int my) { return mx > x && mx < x + w && my > y && my < y + 25; }
    bool is_in_close_button(int mx, int my) { int btn_x = x + w - 22, btn_y = y + 4; return mx >= btn_x && mx < btn_x + 18 && my >= btn_y && my < btn_y + 18; }
    // Minimize ("_") button sits directly to the left of the close button.
    bool is_in_minimize_button(int mx, int my) { int btn_x = x + w - 44, btn_y = y + 4; return mx >= btn_x && mx < btn_x + 18 && my >= btn_y && my < btn_y + 18; }
    virtual void close() { is_closed = true; }
};

class WindowManager {
private:
    Window* windows[16];
    int num_windows;
    int focused_idx;
    int dragging_idx;
    int drag_offset_x, drag_offset_y;

    // New: Desktop & Context Menu management
    DesktopItem desktop_items[64];
    int num_desktop_items;
    int dragging_icon_idx;

    bool context_menu_active;
    int context_menu_x, context_menu_y;
	const char* context_menu_items[8];
    int num_context_menu_items;
    enum ContextType { CTX_DESKTOP, CTX_ICON, CTX_EXPLORER_ITEM }; // ADD CTX_EXPLORER_ITEM
    ContextType current_context;
    int context_icon_idx;
    char context_file_path[128]; // ADD THIS to store the file path    int num_context_menu_items;
    

public:
    WindowManager() : num_windows(0), focused_idx(-1), dragging_idx(-1), 
                      num_desktop_items(0), dragging_icon_idx(-1), 
                      context_menu_active(false) {}
    void show_file_context_menu(int mx, int my, const char* filename, bool is_executable) {
		context_menu_active = true;
		context_menu_x = mx;
		context_menu_y = my;
		current_context = CTX_EXPLORER_ITEM;
		strncpy(context_file_path, filename, 127); // Store the filename for the action
		num_context_menu_items = 0;
		
		if (is_executable) {
			context_menu_items[num_context_menu_items++] = "Run";
		}
		context_menu_items[num_context_menu_items++] = "Edit"; // ADDED THIS LINE
		context_menu_items[num_context_menu_items++] = "Create Shortcut";
		context_menu_items[num_context_menu_items++] = "Copy";
		context_menu_items[num_context_menu_items++] = "Delete";
	}
    // New: Load desktop items from filesystem
    // In WindowManager class
	 void print_to_window(int idx, const char* s) {
        if (idx >= 0 && idx < num_windows) {
            windows[idx]->console_print(s);
        }
    }
	 void put_char_to_focused(char c) {
        if (focused_idx >= 0 && focused_idx < num_windows) {
            windows[focused_idx]->put_char(c);
        }
    }
void load_desktop_items() {
    num_desktop_items = 0;

    // Load items from the root directory
    static fat_dir_entry_t file_list[64]; // Max 64 files on desktop
    int num_files = fat32_list_directory("/", file_list, 64);

    for (int i = 0; i < num_files && num_desktop_items < 64; ++i) {
        fat32_get_fne_from_entry(&file_list[i], desktop_items[num_desktop_items].name);
        strcpy(desktop_items[num_desktop_items].path, desktop_items[num_desktop_items].name);
        
        desktop_items[num_desktop_items].x = 30 + (num_desktop_items % 10) * 70;
        desktop_items[num_desktop_items].y = 30 + (num_desktop_items / 10) * 80;
        
        if (file_list[i].attr & FAT_ATTR_DIRECTORY) {
            desktop_items[num_desktop_items].type = ICON_DIR;
        } else {
            desktop_items[num_desktop_items].type = ICON_FILE;
        }
        num_desktop_items++;
    }
}

    void add_window(Window* win) {
        if (num_windows < 16) {
            if (focused_idx != -1 && focused_idx < num_windows) windows[focused_idx]->has_focus = false;
            windows[num_windows] = win;
            focused_idx = num_windows;
            windows[num_windows]->has_focus = true;
            num_windows++;
        }
    }

    void set_focus(int idx) {
        if (idx < 0 || idx >= num_windows || idx == focused_idx) return;
        if (focused_idx != -1 && focused_idx < num_windows) windows[focused_idx]->has_focus = false;
        Window* focused = windows[idx];
        for (int i = idx; i < num_windows - 1; i++) windows[i] = windows[i+1];
        windows[num_windows - 1] = focused;
        focused_idx = num_windows - 1;
        windows[num_windows - 1]->has_focus = true;
    }

    int get_num_windows() const { return num_windows; }
    int get_focused_idx() const { return focused_idx; }
    Window* get_window(int idx) { 
        if (idx >= 0 && idx < num_windows) return windows[idx];
        return nullptr;
    }

    // Which ELF slot (if any) does the currently FOCUSED window own?
    // -1 if no window is focused, or the focused window isn't a
    // terminal capturing an ELF process. Used to route keystrokes to
    // whichever process the user actually clicked into, instead of
    // just the first process that happens to be waiting for input.
    int get_focused_elf_slot() const {
        if (focused_idx < 0 || focused_idx >= num_windows) return -1;
        return windows[focused_idx]->get_elf_slot();
    }

    void cleanup_closed_windows() {
        if (num_windows == 0) return;
        int current_idx = 0;
        while (current_idx < num_windows) {
            if (windows[current_idx]->is_closed) {
                delete windows[current_idx];
                for (int j = current_idx; j < num_windows - 1; j++) {
                    windows[j] = windows[j + 1];
                }
                num_windows--;
            } else {
                current_idx++;
            }
        }
        
        if (num_windows > 0) {
            focused_idx = num_windows - 1;
            for(int i = 0; i < num_windows; i++) windows[i]->has_focus = false;
            windows[focused_idx]->has_focus = true;
        } else {
            focused_idx = -1;
        }
    }

    // Helper: draw a single 3D-style taskbar button
    void draw_taskbar_button(int bx, int by, int bw, int bh,
                             const char* label, bool active) {
        using namespace ColorPalette;
        uint32_t face  = active ? 0x6080C0u : BUTTON_FACE;
        uint32_t tcolor = active ? TEXT_WHITE : TEXT_BLACK;
        draw_rect_filled(bx, by, bw, 1,  BUTTON_HIGHLIGHT);
        draw_rect_filled(bx, by, 1,  bh, BUTTON_HIGHLIGHT);
        draw_rect_filled(bx + 1, by + bh - 1, bw - 1, 1, BUTTON_SHADOW);
        draw_rect_filled(bx + bw - 1, by + 1,  1, bh - 1, BUTTON_SHADOW);
        draw_rect_filled(bx + 1, by + 1, bw - 2, bh - 2, face);
        // Truncate label to fit
        char tmp[16];
        int maxc = (bw - 8) / 8;
        if (maxc < 1) maxc = 1;
        if (maxc > 15) maxc = 15;
        int li = 0;
        for (; li < maxc && label[li]; li++) tmp[li] = label[li];
        tmp[li] = 0;
        draw_string(tmp, bx + 4, by + bh/2 - 4, tcolor);
    }

    void draw_desktop() {
        using namespace ColorPalette;
        
        // Taskbar base
        draw_rect_filled(0, fb_info.height - 40, fb_info.width, 40, TASKBAR_GRAY);
        draw_rect_filled(0, fb_info.height - 40, fb_info.width, 1, BUTTON_HIGHLIGHT);
        
        // ── "Terminal" launcher button (always present, left-most) ──────────
        int btn_y  = fb_info.height - 36;
        int btn_h  = 32;
        int btn_x  = 4;
        int btn_w  = 80;
        draw_taskbar_button(btn_x, btn_y, btn_w, btn_h, "Terminal", false);
        btn_x += btn_w + 4;

        // ── Per-terminal-window taskbar buttons ──────────────────────────────
        // Every open TerminalWindow gets a button here — not just ones
        // currently running an ELF — so a minimized terminal always has
        // somewhere to be restored from with a single click. Windows are
        // reordered in windows[] every time focus changes (see
        // set_focus()), so walk them in stable get_taskbar_id() order
        // rather than array order, or a window's button would jump
        // around the taskbar every time it was clicked.
        {
            bool shown[16] = { false };
            for (int shown_count = 0; shown_count < num_windows; ++shown_count) {
                // Find the not-yet-shown terminal window with the lowest id.
                int best_i = -1, best_id = 0x7fffffff;
                for (int i = 0; i < num_windows; ++i) {
                    if (shown[i]) continue;
                    int tid = windows[i]->get_taskbar_id();
                    if (tid < 0) { shown[i] = true; continue; } // not a terminal window
                    if (tid < best_id) { best_id = tid; best_i = i; }
                }
                if (best_i < 0) break; // nothing left to show
                shown[best_i] = true;

                Window* tw = windows[best_i];
                bool has_elf = tw->get_elf_slot() >= 0 &&
                                elf_processes[tw->get_elf_slot()].active;

                char label[20];
                int ci = 0;
                label[ci++]='T'; label[ci++]='e'; label[ci++]='r'; label[ci++]='m';
                label[ci++]=' ';
                if (best_id < 10) {
                    label[ci++] = '0' + (char)best_id;
                } else {
                    label[ci++] = '0' + (char)(best_id / 10);
                    label[ci++] = '0' + (char)(best_id % 10);
                }
                if (has_elf) {
                    const char* cmd = elf_processes[tw->get_elf_slot()].cmdline;
                    label[ci++] = ':'; label[ci++] = ' ';
                    for (int k = 0; cmd[k] && ci < 15; k++, ci++) label[ci] = cmd[k];
                } else if (tw->is_minimized) {
                    label[ci++] = ' '; label[ci++] = '['; label[ci++] = '-'; label[ci++] = ']';
                }
                label[ci] = 0;

                bool is_focused = (!tw->is_minimized && focused_idx >= 0 &&
                                    focused_idx < num_windows && windows[focused_idx] == tw);

                draw_taskbar_button(btn_x, btn_y, btn_w, btn_h, label, is_focused);
                btn_x += btn_w + 4;
                if (btn_x + btn_w >= (int)fb_info.width - 100) break; // guard overflow
            }
        }

        // ── Taskbar clock (bottom-right, HH:MM read from CMOS RTC) ──────────
        {
            RTC_Time t = read_rtc();
            // This kernel's snprintf() only understands %d/%s/%c — no %u
            // and no zero-padding width specifiers — so "%02u:%02u" was
            // being emitted almost verbatim (each digit of the format
            // spec printed as a literal character) instead of substituting
            // the actual time, which is why a stray 'u' showed up after
            // every number. Build the zero-padded "HH:MM" string by hand.
            uint8_t hh = t.hour % 24;
            uint8_t mm = t.minute % 60;
            char clock_buf[6];
            clock_buf[0] = '0' + (hh / 10);
            clock_buf[1] = '0' + (hh % 10);
            clock_buf[2] = ':';
            clock_buf[3] = '0' + (mm / 10);
            clock_buf[4] = '0' + (mm % 10);
            clock_buf[5] = '\0';
            int clock_text_w = (int)strlen(clock_buf) * 8; // 8px-wide glyphs, see draw_char()
            int pad = 10;
            int clock_box_w = clock_text_w + pad * 2;
            int clock_box_x = (int)fb_info.width - clock_box_w - 4;
            int clock_box_y = (int)fb_info.height - 36;
            int clock_box_h = 28;

            // Sunken 3D field, matching the taskbar button styling.
            draw_rect_filled(clock_box_x, clock_box_y, clock_box_w, clock_box_h, TASKBAR_DARK);
            draw_rect_filled(clock_box_x, clock_box_y, clock_box_w, 1, ColorPalette::BUTTON_SHADOW);
            draw_rect_filled(clock_box_x, clock_box_y, 1, clock_box_h, ColorPalette::BUTTON_SHADOW);
            draw_rect_filled(clock_box_x, clock_box_y + clock_box_h - 1, clock_box_w, 1, ColorPalette::BUTTON_HIGHLIGHT);
            draw_rect_filled(clock_box_x + clock_box_w - 1, clock_box_y, 1, clock_box_h, ColorPalette::BUTTON_HIGHLIGHT);

            draw_string(clock_buf, clock_box_x + pad, clock_box_y + (clock_box_h - 8) / 2, ColorPalette::TEXT_WHITE);
        }

        // Draw desktop icons
        for (int i = 0; i < num_desktop_items; ++i) {
            bool is_shortcut = strstr(desktop_items[i].name, ".lnk") != nullptr;
            if (desktop_items[i].type == ICON_APP) {
                draw_icon_folder(desktop_items[i].x, desktop_items[i].y);
            } else {
                draw_icon_file(desktop_items[i].x, desktop_items[i].y, is_shortcut);
            }
            draw_string(desktop_items[i].name, desktop_items[i].x, desktop_items[i].y + 35, TEXT_WHITE);
        }
    }

    void execute_context_menu_action(int item_index); // New

    // =============================================================================
    // STATE-BASED WINDOW MANAGER UPDATE - ATOMIC FRAME RENDERING
    // =============================================================================
    void update_all() {
        // Phase 0: Begin new frame
        if (g_render_state.renderPhase == 0) {
            g_render_state.frameComplete = false;
            g_render_state.backgroundCleared = false;
            g_render_state.currentWindow = 0;
            g_render_state.renderPhase = 1;
        }
        
        // Phase 1: Clear background (done once per frame in main loop)
        if (g_render_state.renderPhase == 1) {
            g_render_state.backgroundCleared = true;
            g_render_state.renderPhase = 2;
        }
        
        // Phase 2: Draw desktop and icons
        if (g_render_state.renderPhase == 2) {
            draw_desktop();
            g_render_state.renderPhase = 3;
        }
        
        // Phase 3: Draw windows (all at once to prevent tearing)
        if (g_render_state.renderPhase == 3) {
            for (int i = 0; i < num_windows; i++) {
                if (windows[i] && !windows[i]->is_closed) {
                    windows[i]->draw();
                }
            }
            g_render_state.renderPhase = 4;
        }

        // New Phase 3.5: Draw context menu on top of everything
        if (context_menu_active) {
            int menu_width = 150;
            int item_height = 20;
            int menu_height = num_context_menu_items * item_height;
            draw_rect_filled(context_menu_x, context_menu_y, menu_width, menu_height, ColorPalette::BUTTON_FACE);
            draw_rect_filled(context_menu_x, context_menu_y, menu_width, 1, ColorPalette::BUTTON_HIGHLIGHT);
            draw_rect_filled(context_menu_x, context_menu_y, 1, menu_height, ColorPalette::BUTTON_HIGHLIGHT);
            draw_rect_filled(context_menu_x+menu_width-1, context_menu_y, 1, menu_height, ColorPalette::BUTTON_SHADOW);
            draw_rect_filled(context_menu_x, context_menu_y+menu_height-1, menu_width, 1, ColorPalette::BUTTON_SHADOW);

            for (int i = 0; i < num_context_menu_items; ++i) {
                draw_string(context_menu_items[i], context_menu_x + 5, context_menu_y + 5 + i * item_height, ColorPalette::TEXT_BLACK);
            }
        }
        
        // Phase 4: Update logic
        if (g_render_state.renderPhase == 4) {
            for (int i = 0; i < num_windows; i++) {
                if (windows[i] && !windows[i]->is_closed) {
                    windows[i]->update();
                }
            }
            g_render_state.renderPhase = 5;
        }
        
        // Phase 5: Frame complete
        if (g_render_state.renderPhase == 5) {
            g_render_state.frameComplete = true;
            g_render_state.renderPhase = 0;
            g_render_state.frameNumber++;
        }
    }

    void handle_input(char key, int mx, int my, bool left_down, bool left_clicked, bool right_clicked); // Modified
    void print_to_focused(const char* s);
};

