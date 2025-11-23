#ifndef KEYBOARD_H
#define KEYBOARD_H

#include <stdint.h>
#include <stdbool.h>

/* Keyboard port definitions */
#define KEYBOARD_DATA_PORT      0x60
#define KEYBOARD_STATUS_PORT    0x64
#define KEYBOARD_COMMAND_PORT   0x64

/* Keyboard status register bits */
#define KEYBOARD_STATUS_OUTPUT_FULL     0x01
#define KEYBOARD_STATUS_INPUT_FULL      0x02
#define KEYBOARD_STATUS_SYSTEM          0x04
#define KEYBOARD_STATUS_COMMAND         0x08
#define KEYBOARD_STATUS_LOCKED          0x10
#define KEYBOARD_STATUS_AUX_OUTPUT_FULL 0x20
#define KEYBOARD_STATUS_TIMEOUT         0x40
#define KEYBOARD_STATUS_PARITY_ERROR    0x80

/* Keyboard command bytes */
#define KEYBOARD_COMMAND_READ_CONFIG    0x20
#define KEYBOARD_COMMAND_WRITE_CONFIG   0x60
#define KEYBOARD_COMMAND_DISABLE_MOUSE  0xA7
#define KEYBOARD_COMMAND_ENABLE_MOUSE   0xA8
#define KEYBOARD_COMMAND_DISABLE_KBD    0xAD
#define KEYBOARD_COMMAND_ENABLE_KBD     0xAE
#define KEYBOARD_COMMAND_WRITE_MOUSE    0xD4
#define KEYBOARD_COMMAND_SELF_TEST      0xAA
#define KEYBOARD_COMMAND_INTERFACE_TEST 0xAB
#define KEYBOARD_COMMAND_DISABLE_KBD2   0xA7
#define KEYBOARD_COMMAND_ENABLE_KBD2    0xA8

/* Keyboard configuration byte */
#define KEYBOARD_CONFIG_KBD_INTERRUPT   0x01
#define KEYBOARD_CONFIG_MOUSE_INTERRUPT 0x02
#define KEYBOARD_CONFIG_SYSTEM_FLAG     0x04
#define KEYBOARD_CONFIG_KBD_DISABLED    0x10
#define KEYBOARD_CONFIG_MOUSE_DISABLED  0x20
#define KEYBOARD_CONFIG_SCANCODE        0x40
#define KEYBOARD_CONFIG_RESERVED        0x80

/* Keyboard scancode sets */
#define KEYBOARD_SCANCODE_SET1          1
#define KEYBOARD_SCANCODE_SET2          2
#define KEYBOARD_SCANCODE_SET3          3

/* Key codes */
typedef enum {
    KEY_NONE = 0,
    
    /* Function keys */
    KEY_F1 = 0x3B, KEY_F2 = 0x3C, KEY_F3 = 0x3D, KEY_F4 = 0x3E,
    KEY_F5 = 0x3F, KEY_F6 = 0x40, KEY_F7 = 0x41, KEY_F8 = 0x42,
    KEY_F9 = 0x43, KEY_F10 = 0x44, KEY_F11 = 0x57, KEY_F12 = 0x58,
    
    /* Control keys */
    KEY_ESC = 0x01,
    KEY_BACKSPACE = 0x0E,
    KEY_TAB = 0x0F,
    KEY_ENTER = 0x1C,
    KEY_SPACE = 0x39,
    KEY_LEFT_CTRL = 0x1D,
    KEY_LEFT_SHIFT = 0x2A,
    KEY_RIGHT_SHIFT = 0x36,
    KEY_LEFT_ALT = 0x38,
    KEY_RIGHT_ALT = 0xE0,
    KEY_CAPS_LOCK = 0x3A,
    KEY_NUM_LOCK = 0x45,
    KEY_SCROLL_LOCK = 0x46,
    
    /* Navigation keys */
    KEY_UP = 0x48,
    KEY_DOWN = 0x50,
    KEY_LEFT = 0x4B,
    KEY_RIGHT = 0x4D,
    KEY_HOME = 0x47,
    KEY_END = 0x4F,
    KEY_PAGE_UP = 0x49,
    KEY_PAGE_DOWN = 0x51,
    KEY_INSERT = 0x52,
    KEY_DELETE = 0x53,
    
    /* Special keys */
    KEY_PAUSE = 0xE1,
    KEY_PRINT_SCREEN = 0xE0,
    
    /* ASCII keys */
    KEY_A = 0x1E, KEY_B = 0x30, KEY_C = 0x2E, KEY_D = 0x20,
    KEY_E = 0x12, KEY_F = 0x21, KEY_G = 0x22, KEY_H = 0x23,
    KEY_I = 0x17, KEY_J = 0x24, KEY_K = 0x25, KEY_L = 0x26,
    KEY_M = 0x32, KEY_N = 0x31, KEY_O = 0x18, KEY_P = 0x19,
    KEY_Q = 0x10, KEY_R = 0x13, KEY_S = 0x1F, KEY_T = 0x14,
    KEY_U = 0x16, KEY_V = 0x2F, KEY_W = 0x11, KEY_X = 0x2D,
    KEY_Y = 0x15, KEY_Z = 0x2C,
    
    KEY_0 = 0x0B, KEY_1 = 0x02, KEY_2 = 0x03, KEY_3 = 0x04,
    KEY_4 = 0x05, KEY_5 = 0x06, KEY_6 = 0x07, KEY_7 = 0x08,
    KEY_8 = 0x09, KEY_9 = 0x0A,
    
    /* Special characters */
    KEY_MINUS = 0x0C,
    KEY_EQUAL = 0x0D,
    KEY_LEFT_BRACKET = 0x1A,
    KEY_RIGHT_BRACKET = 0x1B,
    KEY_SEMICOLON = 0x27,
    KEY_QUOTE = 0x28,
    KEY_BACKTICK = 0x29,
    KEY_BACKSLASH = 0x2B,
    KEY_COMMA = 0x33,
    KEY_PERIOD = 0x34,
    KEY_SLASH = 0x35
} key_code_t;

/* Key states */
typedef enum {
    KEY_STATE_RELEASED = 0,
    KEY_STATE_PRESSED = 1
} key_state_t;

/* Keyboard event structure */
typedef struct {
    uint8_t scancode;
    key_code_t key_code;
    key_state_t state;
    bool shift_pressed;
    bool ctrl_pressed;
    bool alt_pressed;
    bool caps_lock;
    bool num_lock;
    bool scroll_lock;
    uint8_t ascii;
} keyboard_event_t;

/* Keyboard buffer */
#define KEYBOARD_BUFFER_SIZE 256
typedef struct {
    keyboard_event_t events[KEYBOARD_BUFFER_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    bool overflow;
} keyboard_buffer_t;

/* Keyboard state */
typedef struct {
    keyboard_buffer_t buffer;
    bool initialized;
    bool enabled;
    uint8_t scancode_set;
    uint8_t config_byte;
    bool shift_pressed;
    bool ctrl_pressed;
    bool alt_pressed;
    bool caps_lock;
    bool num_lock;
    bool scroll_lock;
    bool extended_scancode;
    bool pause_sequence;
    bool print_screen_sequence;
    uint8_t led_status;
    uint32_t key_repeat_delay;
    uint32_t key_repeat_rate;
    uint32_t last_key_time;
    uint8_t last_key_scancode;
    uint32_t key_repeat_count;
    bool auto_repeat_enabled;
    
    /* Pentesting specific features */
    bool keylogger_enabled;
    bool macro_recording;
    bool macro_playback;
    uint8_t macro_buffer[1024];
    uint32_t macro_buffer_size;
    uint32_t macro_buffer_pos;
    bool secure_input_mode;
    char secure_input_buffer[256];
    uint32_t secure_input_pos;
    
    /* Security features */
    bool key_filter_enabled;
    uint8_t blocked_keys[32];
    uint32_t blocked_keys_count;
    bool rate_limiting_enabled;
    uint32_t max_keys_per_second;
    uint32_t keys_this_second;
    uint32_t current_second;
    
    /* Statistics */
    uint32_t total_keys_pressed;
    uint32_t total_keys_released;
    uint32_t buffer_overflows;
    uint32_t invalid_scancodes;
    uint32_t security_violations;
} keyboard_state_t;

/* Keyboard driver functions */
void keyboard_init(void);
void keyboard_enable(void);
void keyboard_disable(void);
void keyboard_reset(void);
bool keyboard_is_initialized(void);
bool keyboard_is_enabled(void);

/* Event handling */
bool keyboard_get_event(keyboard_event_t* event);
bool keyboard_has_events(void);
uint32_t keyboard_get_event_count(void);
void keyboard_flush_buffer(void);

/* Key state functions */
bool keyboard_is_key_pressed(key_code_t key);
bool keyboard_is_key_released(key_code_t key);
bool keyboard_is_modifier_pressed(uint8_t modifier);
uint8_t keyboard_get_led_status(void);
void keyboard_set_leds(uint8_t leds);

/* Configuration */
void keyboard_set_scancode_set(uint8_t set);
uint8_t keyboard_get_scancode_set(void);
void keyboard_set_repeat_rate(uint32_t delay, uint32_t rate);
void keyboard_get_repeat_rate(uint32_t* delay, uint32_t* rate);
void keyboard_set_auto_repeat(bool enable);
bool keyboard_get_auto_repeat(void);

/* Pentesting functions */
void keyboard_enable_keylogger(void);
void keyboard_disable_keylogger(void);
bool keyboard_is_keylogger_enabled(void);
void keyboard_start_macro_recording(void);
void keyboard_stop_macro_recording(void);
void keyboard_play_macro(void);
void keyboard_clear_macro(void);
bool keyboard_is_recording_macro(void);
bool keyboard_is_playing_macro(void);

/* Security functions */
void keyboard_enable_key_filter(void);
void keyboard_disable_key_filter(void);
void keyboard_block_key(uint8_t scancode);
void keyboard_unblock_key(uint8_t scancode);
void keyboard_clear_blocked_keys(void);
void keyboard_enable_rate_limiting(uint32_t max_keys_per_second);
void keyboard_disable_rate_limiting(void);
void keyboard_enable_secure_input(void);
void keyboard_disable_secure_input(void);
bool keyboard_is_secure_input_enabled(void);
const char* keyboard_get_secure_input(void);

/* Statistics */
void keyboard_get_statistics(uint32_t* total_pressed, uint32_t* total_released, 
                           uint32_t* overflows, uint32_t* invalid_scancodes);
void keyboard_reset_statistics(void);

/* Utility functions */
uint8_t keyboard_scancode_to_ascii(uint8_t scancode, bool shift_pressed, bool caps_lock);
key_code_t keyboard_scancode_to_keycode(uint8_t scancode);
bool keyboard_is_extended_scancode(uint8_t scancode);
bool keyboard_is_pause_sequence(uint8_t scancode);
bool keyboard_is_print_screen_sequence(uint8_t scancode);

/* Advanced features */
void keyboard_inject_key(uint8_t scancode);
void keyboard_inject_string(const char* string);
void keyboard_simulate_key_press(key_code_t key);
void keyboard_simulate_key_release(key_code_t key);
void keyboard_send_command(uint8_t command);
uint8_t keyboard_read_data(void);
void keyboard_write_data(uint8_t data);
bool keyboard_wait_for_input(void);
bool keyboard_wait_for_output(void);

/* Hardware functions */
bool keyboard_self_test(void);
bool keyboard_interface_test(void);
void keyboard_enable_interrupts(void);
void keyboard_disable_interrupts(void);
uint8_t keyboard_read_config(void);
void keyboard_write_config(uint8_t config);

/* Pentesting specific key combinations */
#define KEY_COMBO_CTRL_ALT_DEL      0x01
#define KEY_COMBO_CTRL_SHIFT_ESC    0x02
#define KEY_COMBO_ALT_TAB           0x03
#define KEY_COMBO_WIN_R             0x04
#define KEY_COMBO_CTRL_C            0x05
#define KEY_COMBO_CTRL_V            0x06
#define KEY_COMBO_CTRL_Z            0x07

/* Pentesting macros */
#define PENTEST_MACRO_NMAP_SCAN     0x01
#define PENTEST_MACRO_NETSTAT       0x02
#define PENTEST_MACRO_PING_SCAN     0x03
#define PENTEST_MACRO_PORT_SCAN     0x04
#define PENTEST_MACRO_EXPLOIT       0x05

/* Global keyboard state */
extern keyboard_state_t* global_keyboard_state;

#endif /* KEYBOARD_H */