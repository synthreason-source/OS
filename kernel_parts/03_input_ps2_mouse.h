#pragma once
// 03_input_ps2_mouse.h
// PS/2 controller and mouse/keyboard input state.
// Extracted from kernel.cpp (original lines 1443-1572) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.

#define FAT_ATTR_DIRECTORY 0x10
// =============================================================================
// PS/2 AND INPUT SYSTEM (Abbreviated - full implementation as before)
// =============================================================================

struct PS2State {
    uint32_t lastInputCheckTick;
    uint32_t lastOutputCheckTick;
    uint8_t inputAttemptCount;
    uint8_t outputAttemptCount;
};
static PS2State g_ps2state = {0, 0, 0, 0};

#define PS2_DATA_PORT       0x60
#define PS2_STATUS_PORT     0x64
#define PS2_COMMAND_PORT    0x64
#define PS2_CMD_READ_CONFIG     0x20
#define PS2_CMD_WRITE_CONFIG    0x60
#define PS2_CMD_DISABLE_PORT1   0xAD
#define PS2_CMD_ENABLE_PORT1    0xAE
#define PS2_CMD_DISABLE_PORT2   0xA7
#define PS2_CMD_ENABLE_PORT2    0xA8
#define PS2_CMD_TEST_PORT2      0xA9
#define PS2_CMD_TEST_CTRL       0xAA
#define PS2_CMD_WRITE_PORT2     0xD4
#define MOUSE_CMD_RESET         0xFF
#define MOUSE_CMD_RESEND        0xFE
#define MOUSE_CMD_SET_DEFAULTS  0xF6
#define MOUSE_CMD_DISABLE_DATA  0xF5
#define MOUSE_CMD_ENABLE_DATA   0xF4
#define MOUSE_CMD_SET_SAMPLE    0xF3
#define MOUSE_CMD_SET_RESOLUTION 0xE8
#define PS2_STATUS_OUTPUT_FULL  0x01
#define PS2_STATUS_INPUT_FULL   0x02
#define PS2_STATUS_AUX_DATA     0x20
#define PS2_STATUS_TIMEOUT      0x40
#define PS2_ACK                 0xFA
#define PS2_RESEND              0xFE

#define KEY_UP     -1
#define KEY_DOWN   -2
#define KEY_LEFT   -3
#define KEY_RIGHT  -4
#define KEY_DELETE -5
#define KEY_HOME   -6
#define KEY_END    -7

const char sc_ascii_nomod_map[128]={0,0,'1','2','3','4','5','6','7','8','9','0','-','=','\b','\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',0,'a','s','d','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v','b','n','m',',','.','/',0,0,0,' ',0};
const char sc_ascii_shift_map[128]={0,0,'!','@','#','$','%','^','&','*','(',')','_','+','\b','\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n',0,'A','S','D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V','B','N','M','<','>','?',0,0,0,' ',0};
const char sc_ascii_ctrl_map[128]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,'\b','\t','\x11',0,0,0,0,0,0,0,0,'\x10',0,0,'\n',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,' ',0};

bool is_shift_pressed = false;
bool is_ctrl_pressed = false;
int mouse_x = 400, mouse_y = 300;
bool mouse_left_down = false;
bool mouse_left_last_frame = false;
bool mouse_right_down = false;       // New
bool mouse_right_last_frame = false; // New
char last_key_press = 0;

// ── Keyboard queue + modifier state ─────────────────────────────────────────
// poll_input_universal() is called from MANY places per main-loop pass (once at
// the top, then again after every guest tick inside the guest time slice), and
// it used to do `last_key_press = 0;` on entry. A key picked up by one call was
// therefore wiped by the very next call, long before the main loop got to look
// at it -- so while any guest program was running (a browser, an editor...)
// most keystrokes simply vanished, and the terminal "lost" keys whenever one was
// open. It also held a single char, so two keys in one poll lost one.
//
// Fix: decoded keys are appended to this ring; the main loop pops them. Nothing
// is dropped unless 255 keys pile up unread (counted in g_kbd_dropped).
#define KBD_Q_SIZE 256                      // power of two, and uint8_t index arithmetic relies on <= 256
static char    g_kbd_q[KBD_Q_SIZE];
static uint8_t g_kbd_head = 0, g_kbd_tail = 0;
static uint32_t g_kbd_dropped = 0;          // keys lost to a full queue (should stay 0)
static inline void kbd_enqueue(char c) {
    uint8_t n = (uint8_t)((g_kbd_head + 1) & (KBD_Q_SIZE - 1));
    if (n == g_kbd_tail) { g_kbd_dropped++; return; }   // full: drop the newest, but count it
    g_kbd_q[g_kbd_head] = c;
    g_kbd_head = n;
}
static inline char kbd_dequeue() {
    if (g_kbd_tail == g_kbd_head) return 0;
    char c = g_kbd_q[g_kbd_tail];
    g_kbd_tail = (uint8_t)((g_kbd_tail + 1) & (KBD_Q_SIZE - 1));
    return c;
}
static inline bool kbd_pending() { return g_kbd_tail != g_kbd_head; }

// Lock/prefix state for the scancode decoder (05_io_wait_ps2_funcs.h).
static bool g_kbd_caps   = false;
static bool g_kbd_num    = false;           // keypad digits instead of navigation
static bool g_kbd_ext    = false;           // previous byte was the 0xE0 prefix
static int  g_kbd_skip   = 0;               // bytes of a 0xE1 (Pause) sequence still to swallow

// Keypad digit for scancodes 0x47..0x53 while NumLock is on (0 = no char).
static inline char sc_keypad_digit(uint8_t sc) {
    switch (sc) {
        case 0x47: return '7'; case 0x48: return '8'; case 0x49: return '9';
        case 0x4B: return '4'; case 0x4C: return '5'; case 0x4D: return '6';
        case 0x4F: return '1'; case 0x50: return '2'; case 0x51: return '3';
        case 0x52: return '0'; case 0x53: return '.';
        default:   return 0;
    }
}

struct UniversalMouseState {
    int x;
    int y;
    bool left_button;
    bool right_button;
    bool middle_button;
    uint8_t packet_cycle;
    uint8_t packet_buffer[3];
    bool synchronized;
    bool initialized;
};

static UniversalMouseState universal_mouse_state = {400, 300, false, false, false, 0, {0}, false, false};

static void process_universal_mouse_packet(uint8_t data) {
    if (!universal_mouse_state.synchronized) {
        if (data & 0x08) {
            universal_mouse_state.packet_buffer[0] = data;
            universal_mouse_state.packet_cycle = 1;
            universal_mouse_state.synchronized = true;
            return;
        } else {
            return;
        }
    }
    
    universal_mouse_state.packet_buffer[universal_mouse_state.packet_cycle] = data;
    universal_mouse_state.packet_cycle++;
    
    if (universal_mouse_state.packet_cycle >= 3) {
        universal_mouse_state.packet_cycle = 0;
        
        uint8_t flags = universal_mouse_state.packet_buffer[0];
        
        if (!(flags & 0x08)) {
            universal_mouse_state.synchronized = false;
            return;
        }
        
        universal_mouse_state.left_button = flags & 0x01;
        universal_mouse_state.right_button = flags & 0x02;
        universal_mouse_state.middle_button = flags & 0x04;
        
        int8_t dx = (int8_t)universal_mouse_state.packet_buffer[1];
        int8_t dy = (int8_t)universal_mouse_state.packet_buffer[2];
        
        if (flags & 0x40) {
            dx = (dx > 0) ? 127 : -128;
        }
        if (flags & 0x80) {
            dy = (dy > 0) ? 127 : -128;
        }
        
        const int SENSITIVITY = 2;
        int move_x = dx * SENSITIVITY;
        int move_y = dy * SENSITIVITY;
        
        universal_mouse_state.x += move_x;
        universal_mouse_state.y -= move_y;
        
        if (universal_mouse_state.x < 0) universal_mouse_state.x = 0;
        if (universal_mouse_state.y < 0) universal_mouse_state.y = 0;
        if (universal_mouse_state.x >= (int)fb_info.width) 
            universal_mouse_state.x = fb_info.width - 1;
        if (universal_mouse_state.y >= (int)fb_info.height) 
            universal_mouse_state.y = fb_info.height - 1;
        
        universal_mouse_state.synchronized = true;
    }
}
