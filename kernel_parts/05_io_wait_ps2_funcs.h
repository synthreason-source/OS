#pragma once
// 05_io_wait_ps2_funcs.h
// Low-level I/O wait and PS/2 helper routines.
// Extracted from kernel.cpp (original lines 2020-2468) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.

WindowManager wm;


// =============================================================================
// I/O WAIT AND PS/2 FUNCTIONS
// =============================================================================

static inline void io_wait_short() {
    asm volatile("outb %%al, $0x80" : : "a"(0));
}

static inline void io_delay_short() {
    for (volatile int i = 0; i < 1; i++) {
        io_wait_short();
    }
}

static inline void io_delay_medium() {
    for (volatile int i = 0; i < 2; i++) {
        io_wait_short();
    }
}

static inline void io_delay_long() {
    for (volatile int i = 0; i < 10; i++) {
        io_wait_short();
    }
}

static bool ps2_wait_input_ready(uint32_t timeout = 1000) {
    while (timeout--) {
        if (!(inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_FULL)) {
            return true;
        }
        if (timeout % 1000 == 0) io_delay_medium();
    }
    return false;
}

static bool ps2_wait_output_ready(uint32_t timeout = 1000) {
    while (timeout--) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            return true;
        }
        if (timeout % 1000 == 0) io_delay_medium();
    }
    return false;
}

static void ps2_flush_output_buffer() {
    int timeout = 10;
    while ((inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) && timeout--) {
        inb(PS2_DATA_PORT);
        io_delay_medium();
    }
}

static bool ps2_write_command(uint8_t cmd) {
    if (!ps2_wait_input_ready()) return false;
    outb(PS2_COMMAND_PORT, cmd);
    io_delay_medium();
    return true;
}

static bool ps2_write_data(uint8_t data) {
    if (!ps2_wait_input_ready()) return false;
    outb(PS2_DATA_PORT, data);
    io_delay_medium();
    return true;
}

static bool ps2_read_data(uint8_t* data) {
    if (!ps2_wait_output_ready()) return false;
    *data = inb(PS2_DATA_PORT);
    return true;
}

static bool ps2_mouse_write_command(uint8_t cmd, int max_retries = 3) {
    for (int retry = 0; retry < max_retries; retry++) {
        if (!ps2_write_command(PS2_CMD_WRITE_PORT2)) continue;
        if (!ps2_write_data(cmd)) continue;
        
        uint8_t response;
        if (ps2_read_data(&response)) {
            if (response == PS2_ACK) {
                return true;
            } else if (response == PS2_RESEND) {
                io_delay_long();
                continue;
            }
        }
        io_delay_long();
    }
    return false;
}

static bool ps2_mouse_write_with_arg(uint8_t cmd, uint8_t arg) {
    if (!ps2_mouse_write_command(cmd)) return false;
    io_delay_medium();
    return ps2_mouse_write_command(arg);
}

static bool init_ps2_mouse_legacy() {
    outb(0x64, 0xA8);
    io_delay_long();
    
    outb(0x64, 0x20);
    uint8_t status = inb(0x60) | 2;
    status &= ~0x20;
    
    outb(0x64, 0x60);
    outb(0x60, status);
    io_delay_long();
    
    outb(0x64, 0xD4);
    outb(0x60, 0xF6);
    inb(0x60);
    io_delay_long();
    
    outb(0x64, 0xD4);
    outb(0x60, 0xF4);
    inb(0x60);
    io_delay_long();
    
    ps2_flush_output_buffer();
    return true;
}

static inline void pci_write_config_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)device << 11) | ((uint32_t)function << 8) | (offset & 0xFC);
    outl(0xCF8, address);
    outl(0xCFC, value);
}

struct USBLegacyInfo {
    bool has_uhci;
    bool has_ehci;
    bool has_xhci;
    uint64_t legacy_base;
    bool ps2_emulation_active;
    uint16_t pci_bus;
    uint8_t pci_device;
    uint8_t pci_function;
};

static USBLegacyInfo usb_info = {false, false, false, 0, false, 0, 0, 0};

static bool detect_usb_controllers() {
    for (uint16_t bus = 0; bus < 8; bus++) {  /* scan 8 buses: covers real HW and QEMU */
        for (uint8_t device = 0; device < 32; device++) {
            uint32_t vid = pci_read_config_dword(bus, device, 0, 0) & 0xFFFF;
            if (vid == 0xFFFF) continue;  /* slot empty */
            uint32_t class_code = pci_read_config_dword(bus, device, 0, 0x08);
            uint8_t base_class = (class_code >> 24) & 0xFF;
            uint8_t sub_class = (class_code >> 16) & 0xFF;
            uint8_t prog_if = (class_code >> 8) & 0xFF;
            
            if (base_class == 0x0C && sub_class == 0x03) {
                if (prog_if == 0x20) usb_info.has_ehci = true;
                else if (prog_if == 0x30) usb_info.has_xhci = true;
                
                usb_info.pci_bus = bus;
                usb_info.pci_device = device;
                usb_info.pci_function = 0;
                
                uint32_t bar0 = pci_read_config_dword(bus, device, 0, 0x10);
                usb_info.legacy_base = bar0 & 0xFFFFFFF0;
                return true;
            }
        }
    }
    return false;
}

static bool enable_usb_legacy_support() {
    if (usb_info.has_ehci) {
        uint32_t hccparams = pci_read_config_dword(
            usb_info.pci_bus, 
            usb_info.pci_device, 
            usb_info.pci_function, 
            0x08
        );
        
        uint8_t eecp = (hccparams >> 8) & 0xFF;
        
        if (eecp >= 0x40) {
            uint32_t legsup = pci_read_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp
            );
            
            legsup |= (1 << 24);
            pci_write_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp, 
                legsup
            );
            
            for (int i = 0; i < 100; i++) {
                io_delay_long();
                legsup = pci_read_config_dword(
                    usb_info.pci_bus, 
                    usb_info.pci_device, 
                    usb_info.pci_function, 
                    eecp
                );
                if (!(legsup & (1 << 16))) break;
            }
            
            uint32_t usblegctlsts = pci_read_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp + 4
            );
            usblegctlsts &= 0xFFFF0000;
            pci_write_config_dword(
                usb_info.pci_bus, 
                usb_info.pci_device, 
                usb_info.pci_function, 
                eecp + 4, 
                usblegctlsts
            );
            
            return true;
        }
    }
    return false;
}

static bool init_ps2_mouse_hardware() {
    uint8_t data;
    
    if (usb_info.ps2_emulation_active) {
        io_delay_long();
    }
    
    ps2_write_command(PS2_CMD_DISABLE_PORT1);
    io_delay_long();
    ps2_write_command(PS2_CMD_DISABLE_PORT2);
    io_delay_long();
    
    for (int i = 0; i < 16; i++) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            inb(PS2_DATA_PORT);
        }
        io_delay_medium();
    }
    
    if (!ps2_write_command(PS2_CMD_TEST_CTRL)) return false;
    io_delay_long();
    
    bool self_test_passed = false;
    for (int retry = 0; retry < 5; retry++) {
        if (ps2_read_data(&data)) {
            if (data == 0x55) {
                self_test_passed = true;
                break;
            }
        }
        io_delay_long();
    }
    
    if (!self_test_passed) {
        return false;
    }
    
    if (!ps2_write_command(PS2_CMD_READ_CONFIG)) return false;
    if (!ps2_read_data(&data)) return false;
    
    uint8_t config = data;
    config |= 0x03;
    config &= ~0x30;
    
    if (!ps2_write_command(PS2_CMD_WRITE_CONFIG)) return false;
    if (!ps2_write_data(config)) return false;
    io_delay_long();
    
    if (!ps2_write_command(PS2_CMD_TEST_PORT2)) return false;
    io_delay_long();
    
    bool port_test_passed = false;
    if (ps2_read_data(&data)) {
        if (data == 0x00) {
            port_test_passed = true;
        }
    }
    
    if (!port_test_passed) {
        return false;
    }
    
    if (!ps2_write_command(PS2_CMD_ENABLE_PORT2)) return false;
    io_delay_long();
    
    if (!ps2_mouse_write_command(MOUSE_CMD_RESET)) return false;
    
    uint32_t bat_timeout = 500;
    bool bat_complete = false;
    
    while (bat_timeout-- > 0) {
        if (ps2_read_data(&data)) {
            if (data == 0xAA) {
                bat_complete = true;
                io_delay_medium();
                ps2_read_data(&data);
                break;
            } else if (data == 0xFC) {
                io_delay_long();
                ps2_mouse_write_command(MOUSE_CMD_RESET);
                bat_timeout = 250;
            }
        }
        if (bat_timeout % 100 == 0) {
            io_delay_medium();
        }
    }
    
    if (!bat_complete) {
        return false;
    }
    
    io_delay_long();
    
    if (!ps2_mouse_write_command(MOUSE_CMD_SET_DEFAULTS)) return false;
    io_delay_long();
    
    if (!ps2_mouse_write_with_arg(MOUSE_CMD_SET_SAMPLE, 100)) {
    }
    io_delay_long();
    
    if (!ps2_mouse_write_with_arg(MOUSE_CMD_SET_RESOLUTION, 3)) {
    }
    io_delay_long();
    
    outb(0x64, 0xD4);
    io_delay_medium();
    outb(0x60, 0xE6);
    io_delay_medium();
    inb(0x60);
    io_delay_medium();
    
    if (!ps2_mouse_write_command(MOUSE_CMD_ENABLE_DATA)) return false;
    io_delay_long();
    
    ps2_write_command(PS2_CMD_ENABLE_PORT1);
    io_delay_long();
    
    for (int i = 0; i < 16; i++) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            inb(PS2_DATA_PORT);
        }
        io_delay_short();
    }
    
    return true;
}

bool initialize_universal_mouse() {
    universal_mouse_state.initialized = false;
    universal_mouse_state.synchronized = false;
    universal_mouse_state.packet_cycle = 0;
    universal_mouse_state.x = fb_info.width / 2;
    universal_mouse_state.y = fb_info.height / 2;
    
    bool has_usb = detect_usb_controllers();
    if (has_usb) {
        wm.print_to_focused("USB controllers detected...\n");
        if (enable_usb_legacy_support()) {
            wm.print_to_focused("USB Legacy PS/2 emulation enabled.\n");
        }
    }
    
    wm.print_to_focused("Initializing PS/2 mouse interface...\n");
    
    if (init_ps2_mouse_hardware()) {
        universal_mouse_state.initialized = true;
        wm.print_to_focused("PS/2 mouse initialized (hardware method).\n");
        return true;
    }
    
    wm.print_to_focused("Trying legacy PS/2 initialization...\n");
    if (init_ps2_mouse_legacy()) {
        universal_mouse_state.initialized = true;
        wm.print_to_focused("PS/2 mouse initialized (legacy method).\n");
        return true;
    }
    
    wm.print_to_focused("ERROR: Mouse initialization failed.\n");
    return false;
}
void poll_input_universal() {
    last_key_press = 0;
    // Non-blocking: only read if data is immediately available

    for (int iterations = 0; iterations < 16; iterations++) {
        uint8_t status = inb(PS2_STATUS_PORT);
        if (!(status & PS2_STATUS_OUTPUT_FULL)) break;

        uint8_t data = inb(PS2_DATA_PORT);

        if (status & PS2_STATUS_AUX_DATA) {
            process_universal_mouse_packet(data);
        } else {
            bool is_press = !(data & 0x80);
            uint8_t scancode = data & 0x7F;

            if (scancode == 0 || scancode > 0x58) continue;

            if (scancode == 0x2A || scancode == 0x36) {
                is_shift_pressed = is_press;
            } else if (scancode == 0x1D) {
                is_ctrl_pressed = is_press;
            } else if (is_press) {
                switch(scancode) {
                    case 0x48: last_key_press = KEY_UP; break;
                    case 0x50: last_key_press = KEY_DOWN; break;
                    case 0x4B: last_key_press = KEY_LEFT; break;
                    case 0x4D: last_key_press = KEY_RIGHT; break;
                    case 0x53: last_key_press = KEY_DELETE; break;
                    case 0x47: last_key_press = KEY_HOME; break;
                    case 0x4F: last_key_press = KEY_END; break;
                    default: {
                        const char* map = is_ctrl_pressed ? sc_ascii_ctrl_map :
                                          (is_shift_pressed ? sc_ascii_shift_map : sc_ascii_nomod_map);
                        if (scancode < 128 && map[scancode] != 0) {
                            last_key_press = map[scancode];
                        }
                    }
                }
            }
        }
    }

    mouse_x = universal_mouse_state.x;
    mouse_y = universal_mouse_state.y;
    mouse_left_down = universal_mouse_state.left_button;
    mouse_right_down = universal_mouse_state.right_button; // New
}
void draw_cursor(int x, int y, uint32_t color) { 
    for(int i=0;i<12;i++) put_pixel_back(x,y+i,color); 
    for(int i=0;i<8;i++) put_pixel_back(x+i,y+i,color); 
    for(int i=0;i<4;i++) put_pixel_back(x+i,y+(11-i),color); 
}

// =============================================================================
// CURSOR-ONLY FAST PATH -- fixes "mouse is too heavy to compute"
// =============================================================================
// The main loop used to treat EVERY mouse-move event exactly like a click
// or keypress: full clear_screen(), full redraw of the desktop, every
// icon, every window's contents and the taskbar/clock, then a full
// 1024x768 (3MB) backbuffer->framebuffer blit -- just to move an 8x12
// pixel cursor glyph one pixel. WindowManager::handle_input() already
// early-returns doing nothing at all for a plain hover-move (no button
// down, no click edge -- see its left_clicked/left_down guards in
// 10_window_manager_impl.h), so almost all of that recompute was pure
// waste on the overwhelmingly common case of just moving the pointer
// around. The functions below let the main loop skip straight to
// "erase old cursor pixels, draw new cursor pixels" by writing directly
// to the live framebuffer instead of going through backbuffer+full-blit.
//
// Precondition for correctness: the backbuffer must be cursor-free at
// all times (draw_cursor() above, which draws INTO the backbuffer, must
// not be used on the hot path any more -- only draw_cursor_to_screen()
// below, which never touches the backbuffer). That's what makes it safe
// to "erase" the old glyph by copying straight from the backbuffer.

static inline void put_pixel_fb_direct(int x, int y, uint32_t color) {
    if (!fb_info.ptr) return;
    if (x < 0 || y < 0 || x >= (int)fb_info.width || y >= (int)fb_info.height) return;
    uint32_t* row = (uint32_t*)((uint8_t*)fb_info.ptr + (uint32_t)y * fb_info.pitch);
    row[x] = color;
}

// Bounding box actually touched by draw_cursor()'s three loops above:
// column x (rows y..y+11), diagonal (x..x+7, y..y+7), and the short
// tail (x..x+3, y+8..y+11) -- so 8 columns wide, 12 rows tall.
#define CURSOR_BBOX_W 8
#define CURSOR_BBOX_H 12

static int  g_cursor_screen_x = -1;
static int  g_cursor_screen_y = -1;
static bool g_cursor_screen_drawn = false;

// True once a full frame has been pushed to the screen via swap_buffers()
// with no cursor drawn into the backbuffer -- i.e. it's safe to "erase"
// the cursor by copying its old rectangle straight back from the
// backbuffer. Cleared any time something other than the cursor position
// changes, forcing the next frame back through the full repaint path.
bool g_backbuffer_is_clean_on_screen = false;

// Restores whatever was under the last-drawn cursor position, straight
// from the (guaranteed cursor-free) backbuffer, directly onto the
// framebuffer. Cheap: at most CURSOR_BBOX_W*CURSOR_BBOX_H pixels.
static void erase_cursor_from_screen() {
    if (!g_cursor_screen_drawn || !backbuffer) return;
    for (int dy = 0; dy < CURSOR_BBOX_H; dy++) {
        int sy = g_cursor_screen_y + dy;
        if (sy < 0 || sy >= (int)fb_info.height) continue;
        for (int dx = 0; dx < CURSOR_BBOX_W; dx++) {
            int sx = g_cursor_screen_x + dx;
            if (sx < 0 || sx >= (int)fb_info.width) continue;
            put_pixel_fb_direct(sx, sy, backbuffer[sy * fb_info.width + sx]);
        }
    }
    // These are scattered, non-sequential stores -- unlike swap_buffers()'s
    // single big `rep movsl` burst, which is the access pattern real
    // hardware's Write-Combining framebuffer mapping (see
    // setup_framebuffer_write_combining() in
    // 02_boot_info_and_graphics_driver.h) is actually fast *and correct*
    // for. WC stores can sit in the CPU's write-combining buffers and
    // aren't guaranteed visible on screen until something drains them;
    // scattered small writes like this one can leave a buffer partially
    // filled indefinitely. sfence forces any pending WC stores out now,
    // rather than leaving the erased cursor pixels to show up whenever
    // something unrelated happens to evict the buffer later (which is
    // what "cursor freezes, then jumps/disappears" looks like).
    asm volatile("sfence" ::: "memory");
    g_cursor_screen_drawn = false;
}

// Draws the cursor glyph straight onto the framebuffer -- never into the
// backbuffer, so the backbuffer stays a valid "cursor erased" reference
// for erase_cursor_from_screen() on the next move.
static void draw_cursor_to_screen(int x, int y, uint32_t color) {
    for (int i = 0; i < 12; i++) put_pixel_fb_direct(x, y + i, color);
    for (int i = 0; i < 8;  i++) put_pixel_fb_direct(x + i, y + i, color);
    for (int i = 0; i < 4;  i++) put_pixel_fb_direct(x + i, y + (11 - i), color);
    // See the comment in erase_cursor_from_screen() -- same WC hazard
    // applies here, in the other direction (drawing the new glyph).
    asm volatile("sfence" ::: "memory");
    g_cursor_screen_x = x;
    g_cursor_screen_y = y;
    g_cursor_screen_drawn = true;
}

