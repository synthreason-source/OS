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

const char sc_ascii_nomod_map[]={0,0,'1','2','3','4','5','6','7','8','9','0','-','=','\b','\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',0,'a','s','d','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v','b','n','m',',','.','/',0,0,0,' ',0};
const char sc_ascii_shift_map[]={0,0,'!','@','#','$','%','^','&','*','(',')','_','+','\b','\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n',0,'A','S','D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V','B','N','M','<','>','?',0,0,0,' ',0};
const char sc_ascii_ctrl_map[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,'\b','\t','\x11',0,0,0,0,0,0,0,0,'\x10',0,0,'\n',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,' ',0};

bool is_shift_pressed = false;
bool is_ctrl_pressed = false;
int mouse_x = 400, mouse_y = 300;
bool mouse_left_down = false;
bool mouse_left_last_frame = false;
bool mouse_right_down = false;       // New
bool mouse_right_last_frame = false; // New
char last_key_press = 0;

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
