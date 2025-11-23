#include "keyboard.h"
#include "../kernel/memory.h"
#include "../kernel/interrupt.h"
#include "../drivers/vga.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

/* Global keyboard state */
keyboard_state_t* global_keyboard_state = NULL;
bool keyboard_initialized = false;

/* Scancode to ASCII conversion tables */
static const uint8_t scancode_to_ascii_set1[] = {
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 'a', 's',
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
    'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const uint8_t scancode_to_ascii_set1_shift[] = {
    0,  27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 'A', 'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 'Z', 'X', 'C', 'V',
    'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Extended scancodes */
static const uint8_t extended_scancodes[] = {
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF
};

/* Pentesting macro definitions */
static const char* pentest_macros[] = {
    [PENTEST_MACRO_NMAP_SCAN] = "nmap -sS -O -sV target\n",
    [PENTEST_MACRO_NETSTAT] = "netstat -tulpn\n",
    [PENTEST_MACRO_PING_SCAN] = "ping -c 4 target\n",
    [PENTEST_MACRO_PORT_SCAN] = "nmap -p- target\n",
    [PENTEST_MACRO_EXPLOIT] = "msfconsole\n"
};

/* Initialize keyboard driver */
void keyboard_init(void) {
    if (keyboard_initialized) return;
    
    /* Allocate keyboard state */
    global_keyboard_state = (keyboard_state_t*)kmalloc(sizeof(keyboard_state_t));
    if (!global_keyboard_state) return;
    
    memory_zero(global_keyboard_state, sizeof(keyboard_state_t));
    
    /* Initialize state */
    global_keyboard_state->initialized = true;
    global_keyboard_state->enabled = false;
    global_keyboard_state->scancode_set = KEYBOARD_SCANCODE_SET1;
    global_keyboard_state->config_byte = 0;
    global_keyboard_state->shift_pressed = false;
    global_keyboard_state->ctrl_pressed = false;
    global_keyboard_state->alt_pressed = false;
    global_keyboard_state->caps_lock = false;
    global_keyboard_state->num_lock = false;
    global_keyboard_state->scroll_lock = false;
    global_keyboard_state->extended_scancode = false;
    global_keyboard_state->pause_sequence = false;
    global_keyboard_state->print_screen_sequence = false;
    global_keyboard_state->led_status = 0;
    global_keyboard_state->key_repeat_delay = 500;  /* 500ms */
    global_keyboard_state->key_repeat_rate = 33;    /* 30 chars per second */
    global_keyboard_state->last_key_time = 0;
    global_keyboard_state->last_key_scancode = 0;
    global_keyboard_state->key_repeat_count = 0;
    global_keyboard_state->auto_repeat_enabled = true;
    
    /* Pentesting features */
    global_keyboard_state->keylogger_enabled = false;
    global_keyboard_state->macro_recording = false;
    global_keyboard_state->macro_playback = false;
    global_keyboard_state->macro_buffer_size = 0;
    global_keyboard_state->macro_buffer_pos = 0;
    global_keyboard_state->secure_input_mode = false;
    global_keyboard_state->secure_input_pos = 0;
    
    /* Security features */
    global_keyboard_state->key_filter_enabled = false;
    global_keyboard_state->blocked_keys_count = 0;
    global_keyboard_state->rate_limiting_enabled = false;
    global_keyboard_state->max_keys_per_second = 100;
    global_keyboard_state->keys_this_second = 0;
    global_keyboard_state->current_second = 0;
    
    /* Statistics */
    global_keyboard_state->total_keys_pressed = 0;
    global_keyboard_state->total_keys_released = 0;
    global_keyboard_state->buffer_overflows = 0;
    global_keyboard_state->invalid_scancodes = 0;
    global_keyboard_state->security_violations = 0;
    
    /* Reset and test keyboard */
    keyboard_reset();
    keyboard_self_test();
    keyboard_interface_test();
    
    /* Enable keyboard */
    keyboard_enable();
    
    keyboard_initialized = true;
}

/* Enable keyboard */
void keyboard_enable(void) {
    if (!global_keyboard_state || !global_keyboard_state->initialized) return;
    
    /* Enable keyboard interrupts */
    keyboard_enable_interrupts();
    
    /* Enable keyboard device */
    keyboard_send_command(KEYBOARD_COMMAND_ENABLE_KBD);
    
    global_keyboard_state->enabled = true;
}

/* Disable keyboard */
void keyboard_disable(void) {
    if (!global_keyboard_state || !global_keyboard_state->initialized) return;
    
    /* Disable keyboard device */
    keyboard_send_command(KEYBOARD_COMMAND_DISABLE_KBD);
    
    /* Disable keyboard interrupts */
    keyboard_disable_interrupts();
    
    global_keyboard_state->enabled = false;
}

/* Reset keyboard */
void keyboard_reset(void) {
    if (!global_keyboard_state || !global_keyboard_state->initialized) return;
    
    /* Reset keyboard controller */
    keyboard_send_command(KEYBOARD_COMMAND_WRITE_CONFIG);
    keyboard_write_data(0x00);
    
    /* Reset keyboard device */
    keyboard_write_data(0xFF);  /* Reset command */
    
    /* Wait for ACK */
    keyboard_wait_for_input();
    
    /* Clear buffer */
    keyboard_flush_buffer();
    
    /* Reset state */
    global_keyboard_state->shift_pressed = false;
    global_keyboard_state->ctrl_pressed = false;
    global_keyboard_state->alt_pressed = false;
    global_keyboard_state->extended_scancode = false;
    global_keyboard_state->pause_sequence = false;
    global_keyboard_state->print_screen_sequence = false;
}

/* Check if initialized */
bool keyboard_is_initialized(void) {
    return keyboard_initialized && global_keyboard_state && global_keyboard_state->initialized;
}

/* Check if enabled */
bool keyboard_is_enabled(void) {
    return keyboard_initialized && global_keyboard_state && global_keyboard_state->enabled;
}

/* Get event from buffer */
bool keyboard_get_event(keyboard_event_t* event) {
    if (!global_keyboard_state || !event) return false;
    if (global_keyboard_state->buffer.count == 0) return false;
    
    *event = global_keyboard_state->buffer.events[global_keyboard_state->buffer.head];
    global_keyboard_state->buffer.head = (global_keyboard_state->buffer.head + 1) % KEYBOARD_BUFFER_SIZE;
    global_keyboard_state->buffer.count--;
    
    return true;
}

/* Check if events available */
bool keyboard_has_events(void) {
    return global_keyboard_state && global_keyboard_state->buffer.count > 0;
}

/* Get event count */
uint32_t keyboard_get_event_count(void) {
    return global_keyboard_state ? global_keyboard_state->buffer.count : 0;
}

/* Flush buffer */
void keyboard_flush_buffer(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->buffer.head = 0;
    global_keyboard_state->buffer.tail = 0;
    global_keyboard_state->buffer.count = 0;
    global_keyboard_state->buffer.overflow = false;
}

/* Check if key is pressed */
bool keyboard_is_key_pressed(key_code_t key) {
    if (!global_keyboard_state) return false;
    
    /* Check buffer for key press events */
    uint32_t saved_head = global_keyboard_state->buffer.head;
    uint32_t saved_count = global_keyboard_state->buffer.count;
    uint32_t current = saved_head;
    
    for (uint32_t i = 0; i < saved_count; i++) {
        keyboard_event_t* event = &global_keyboard_state->buffer.events[current];
        if (event->key_code == key && event->state == KEY_STATE_PRESSED) {
            return true;
        }
        current = (current + 1) % KEYBOARD_BUFFER_SIZE;
    }
    
    return false;
}

/* Check if key is released */
bool keyboard_is_key_released(key_code_t key) {
    if (!global_keyboard_state) return false;
    
    /* Check buffer for key release events */
    uint32_t saved_head = global_keyboard_state->buffer.head;
    uint32_t saved_count = global_keyboard_state->buffer.count;
    uint32_t current = saved_head;
    
    for (uint32_t i = 0; i < saved_count; i++) {
        keyboard_event_t* event = &global_keyboard_state->buffer.events[current];
        if (event->key_code == key && event->state == KEY_STATE_RELEASED) {
            return true;
        }
        current = (current + 1) % KEYBOARD_BUFFER_SIZE;
    }
    
    return false;
}

/* Check if modifier is pressed */
bool keyboard_is_modifier_pressed(uint8_t modifier) {
    if (!global_keyboard_state) return false;
    
    switch (modifier) {
        case KEY_LEFT_SHIFT:
        case KEY_RIGHT_SHIFT:
            return global_keyboard_state->shift_pressed;
        case KEY_LEFT_CTRL:
            return global_keyboard_state->ctrl_pressed;
        case KEY_LEFT_ALT:
        case KEY_RIGHT_ALT:
            return global_keyboard_state->alt_pressed;
        case KEY_CAPS_LOCK:
            return global_keyboard_state->caps_lock;
        case KEY_NUM_LOCK:
            return global_keyboard_state->num_lock;
        case KEY_SCROLL_LOCK:
            return global_keyboard_state->scroll_lock;
        default:
            return false;
    }
}

/* Get LED status */
uint8_t keyboard_get_led_status(void) {
    return global_keyboard_state ? global_keyboard_state->led_status : 0;
}

/* Set LEDs */
void keyboard_set_leds(uint8_t leds) {
    if (!global_keyboard_state || !global_keyboard_state->initialized) return;
    
    global_keyboard_state->led_status = leds;
    
    /* Send LED command to keyboard */
    keyboard_write_data(0xED);  /* Set LEDs command */
    keyboard_wait_for_input();
    keyboard_write_data(leds);  /* LED status */
    keyboard_wait_for_input();
}

/* Set scancode set */
void keyboard_set_scancode_set(uint8_t set) {
    if (!global_keyboard_state || set < 1 || set > 3) return;
    
    global_keyboard_state->scancode_set = set;
    
    /* Send scancode set command */
    keyboard_write_data(0xF0);  /* Set scancode set command */
    keyboard_wait_for_input();
    keyboard_write_data(set);    /* Scancode set number */
    keyboard_wait_for_input();
}

/* Get scancode set */
uint8_t keyboard_get_scancode_set(void) {
    return global_keyboard_state ? global_keyboard_state->scancode_set : 0;
}

/* Set repeat rate */
void keyboard_set_repeat_rate(uint32_t delay, uint32_t rate) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->key_repeat_delay = delay;
    global_keyboard_state->key_repeat_rate = rate;
    
    /* Send repeat rate command */
    keyboard_write_data(0xF3);  /* Set typematic rate command */
    keyboard_wait_for_input();
    
    /* Calculate and send rate/delay value */
    uint8_t rate_value = 0;
    if (rate > 0) {
        rate_value = (uint8_t)(30 - (rate / 10));  /* Approximate conversion */
        if (rate_value > 0x1F) rate_value = 0x1F;
    }
    
    keyboard_write_data(rate_value);
    keyboard_wait_for_input();
}

/* Get repeat rate */
void keyboard_get_repeat_rate(uint32_t* delay, uint32_t* rate) {
    if (!global_keyboard_state || !delay || !rate) return;
    
    *delay = global_keyboard_state->key_repeat_delay;
    *rate = global_keyboard_state->key_repeat_rate;
}

/* Set auto repeat */
void keyboard_set_auto_repeat(bool enable) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->auto_repeat_enabled = enable;
}

/* Get auto repeat */
bool keyboard_get_auto_repeat(void) {
    return global_keyboard_state ? global_keyboard_state->auto_repeat_enabled : false;
}

/* Enable keylogger */
void keyboard_enable_keylogger(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->keylogger_enabled = true;
    vga_print_info("Keylogger enabled");
}

/* Disable keylogger */
void keyboard_disable_keylogger(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->keylogger_enabled = false;
    vga_print_info("Keylogger disabled");
}

/* Check if keylogger enabled */
bool keyboard_is_keylogger_enabled(void) {
    return global_keyboard_state ? global_keyboard_state->keylogger_enabled : false;
}

/* Start macro recording */
void keyboard_start_macro_recording(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->macro_recording = true;
    global_keyboard_state->macro_buffer_size = 0;
    global_keyboard_state->macro_buffer_pos = 0;
    
    vga_print_info("Macro recording started");
}

/* Stop macro recording */
void keyboard_stop_macro_recording(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->macro_recording = false;
    vga_print_info("Macro recording stopped");
}

/* Play macro */
void keyboard_play_macro(void) {
    if (!global_keyboard_state || global_keyboard_state->macro_buffer_size == 0) return;
    
    global_keyboard_state->macro_playback = true;
    global_keyboard_state->macro_buffer_pos = 0;
    
    vga_print_info("Playing macro");
}

/* Clear macro */
void keyboard_clear_macro(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->macro_buffer_size = 0;
    global_keyboard_state->macro_buffer_pos = 0;
    
    vga_print_info("Macro cleared");
}

/* Check if recording macro */
bool keyboard_is_recording_macro(void) {
    return global_keyboard_state ? global_keyboard_state->macro_recording : false;
}

/* Check if playing macro */
bool keyboard_is_playing_macro(void) {
    return global_keyboard_state ? global_keyboard_state->macro_playback : false;
}

/* Enable key filter */
void keyboard_enable_key_filter(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->key_filter_enabled = true;
    vga_print_info("Key filter enabled");
}

/* Disable key filter */
void keyboard_disable_key_filter(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->key_filter_enabled = false;
    vga_print_info("Key filter disabled");
}

/* Block key */
void keyboard_block_key(uint8_t scancode) {
    if (!global_keyboard_state || global_keyboard_state->blocked_keys_count >= 32) return;
    
    global_keyboard_state->blocked_keys[global_keyboard_state->blocked_keys_count++] = scancode;
}

/* Unblock key */
void keyboard_unblock_key(uint8_t scancode) {
    if (!global_keyboard_state) return;
    
    for (uint32_t i = 0; i < global_keyboard_state->blocked_keys_count; i++) {
        if (global_keyboard_state->blocked_keys[i] == scancode) {
            /* Shift remaining keys */
            for (uint32_t j = i; j < global_keyboard_state->blocked_keys_count - 1; j++) {
                global_keyboard_state->blocked_keys[j] = global_keyboard_state->blocked_keys[j + 1];
            }
            global_keyboard_state->blocked_keys_count--;
            break;
        }
    }
}

/* Clear blocked keys */
void keyboard_clear_blocked_keys(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->blocked_keys_count = 0;
}

/* Enable rate limiting */
void keyboard_enable_rate_limiting(uint32_t max_keys_per_second) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->rate_limiting_enabled = true;
    global_keyboard_state->max_keys_per_second = max_keys_per_second;
    global_keyboard_state->keys_this_second = 0;
    global_keyboard_state->current_second = 0;
    
    vga_printf("Rate limiting enabled: %u keys/second\n", max_keys_per_second);
}

/* Disable rate limiting */
void keyboard_disable_rate_limiting(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->rate_limiting_enabled = false;
    vga_print_info("Rate limiting disabled");
}

/* Enable secure input */
void keyboard_enable_secure_input(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->secure_input_mode = true;
    global_keyboard_state->secure_input_pos = 0;
    memory_zero(global_keyboard_state->secure_input_buffer, sizeof(global_keyboard_state->secure_input_buffer));
    
    vga_print_info("Secure input mode enabled");
}

/* Disable secure input */
void keyboard_disable_secure_input(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->secure_input_mode = false;
    global_keyboard_state->secure_input_pos = 0;
    
    vga_print_info("Secure input mode disabled");
}

/* Check if secure input enabled */
bool keyboard_is_secure_input_enabled(void) {
    return global_keyboard_state ? global_keyboard_state->secure_input_mode : false;
}

/* Get secure input */
const char* keyboard_get_secure_input(void) {
    return global_keyboard_state ? global_keyboard_state->secure_input_buffer : NULL;
}

/* Get statistics */
void keyboard_get_statistics(uint32_t* total_pressed, uint32_t* total_released, 
                           uint32_t* overflows, uint32_t* invalid_scancodes) {
    if (!global_keyboard_state) return;
    
    if (total_pressed) *total_pressed = global_keyboard_state->total_keys_pressed;
    if (total_released) *total_released = global_keyboard_state->total_keys_released;
    if (overflows) *overflows = global_keyboard_state->buffer_overflows;
    if (invalid_scancodes) *invalid_scancodes = global_keyboard_state->invalid_scancodes;
}

/* Reset statistics */
void keyboard_reset_statistics(void) {
    if (!global_keyboard_state) return;
    
    global_keyboard_state->total_keys_pressed = 0;
    global_keyboard_state->total_keys_released = 0;
    global_keyboard_state->buffer_overflows = 0;
    global_keyboard_state->invalid_scancodes = 0;
    global_keyboard_state->security_violations = 0;
}

/* Convert scancode to ASCII */
uint8_t keyboard_scancode_to_ascii(uint8_t scancode, bool shift_pressed, bool caps_lock) {
    if (scancode >= sizeof(scancode_to_ascii_set1)) return 0;
    
    if (shift_pressed ^ caps_lock) {
        return scancode_to_ascii_set1_shift[scancode];
    } else {
        return scancode_to_ascii_set1[scancode];
    }
}

/* Convert scancode to keycode */
key_code_t keyboard_scancode_to_keycode(uint8_t scancode) {
    if (scancode >= 0x80) return KEY_NONE;  /* Release codes */
    
    switch (scancode) {
        case 0x01: return KEY_ESC;
        case 0x0E: return KEY_BACKSPACE;
        case 0x0F: return KEY_TAB;
        case 0x1C: return KEY_ENTER;
        case 0x1D: return KEY_LEFT_CTRL;
        case 0x1E: return KEY_A;
        case 0x1F: return KEY_S;
        case 0x20: return KEY_D;
        case 0x21: return KEY_F;
        case 0x22: return KEY_G;
        case 0x23: return KEY_H;
        case 0x24: return KEY_J;
        case 0x25: return KEY_K;
        case 0x26: return KEY_L;
        case 0x27: return KEY_SEMICOLON;
        case 0x28: return KEY_QUOTE;
        case 0x29: return KEY_BACKTICK;
        case 0x2A: return KEY_LEFT_SHIFT;
        case 0x2B: return KEY_BACKSLASH;
        case 0x2C: return KEY_Z;
        case 0x2D: return KEY_X;
        case 0x2E: return KEY_C;
        case 0x2F: return KEY_V;
        case 0x30: return KEY_B;
        case 0x31: return KEY_N;
        case 0x32: return KEY_M;
        case 0x33: return KEY_COMMA;
        case 0x34: return KEY_PERIOD;
        case 0x35: return KEY_SLASH;
        case 0x36: return KEY_RIGHT_SHIFT;
        case 0x38: return KEY_LEFT_ALT;
        case 0x39: return KEY_SPACE;
        case 0x3A: return KEY_CAPS_LOCK;
        case 0x3B: return KEY_F1;
        case 0x3C: return KEY_F2;
        case 0x3D: return KEY_F3;
        case 0x3E: return KEY_F4;
        case 0x3F: return KEY_F5;
        case 0x40: return KEY_F6;
        case 0x41: return KEY_F7;
        case 0x42: return KEY_F8;
        case 0x43: return KEY_F9;
        case 0x44: return KEY_F10;
        case 0x45: return KEY_NUM_LOCK;
        case 0x46: return KEY_SCROLL_LOCK;
        case 0x47: return KEY_HOME;
        case 0x48: return KEY_UP;
        case 0x49: return KEY_PAGE_UP;
        case 0x4B: return KEY_LEFT;
        case 0x4D: return KEY_RIGHT;
        case 0x4F: return KEY_END;
        case 0x50: return KEY_DOWN;
        case 0x51: return KEY_PAGE_DOWN;
        case 0x52: return KEY_INSERT;
        case 0x53: return KEY_DELETE;
        case 0x57: return KEY_F11;
        case 0x58: return KEY_F12;
        default:
            if (scancode >= 0x02 && scancode <= 0x0D) {
                /* Number keys */
                return KEY_1 + (scancode - 0x02);
            }
            return KEY_NONE;
    }
}

/* Check if extended scancode */
bool keyboard_is_extended_scancode(uint8_t scancode) {
    return scancode == 0xE0 || scancode == 0xE1;
}

/* Check if pause sequence */
bool keyboard_is_pause_sequence(uint8_t scancode) {
    return scancode == 0xE1;
}

/* Check if print screen sequence */
bool keyboard_is_print_screen_sequence(uint8_t scancode) {
    return scancode == 0xE0;
}

/* Inject key */
void keyboard_inject_key(uint8_t scancode) {
    if (!global_keyboard_state) return;
    
    /* Process the injected key */
    keyboard_handle_interrupt(scancode);
}

/* Inject string */
void keyboard_inject_string(const char* string) {
    if (!string) return;
    
    while (*string) {
        /* Convert ASCII to scancode and inject */
        uint8_t scancode = ascii_to_scancode(*string);
        if (scancode != 0) {
            keyboard_inject_key(scancode);
        }
        string++;
    }
}

/* Simulate key press */
void keyboard_simulate_key_press(key_code_t key) {
    if (!global_keyboard_state) return;
    
    uint8_t scancode = keycode_to_scancode(key);
    if (scancode != 0) {
        keyboard_inject_key(scancode);
    }
}

/* Simulate key release */
void keyboard_simulate_key_release(key_code_t key) {
    if (!global_keyboard_state) return;
    
    uint8_t scancode = keycode_to_scancode(key);
    if (scancode != 0) {
        keyboard_inject_key(scancode | 0x80);  /* Release code */
    }
}

/* Send command */
void keyboard_send_command(uint8_t command) {
    /* Wait for input buffer to be clear */
    while (inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_INPUT_FULL) {
        /* Busy wait */
    }
    
    /* Send command */
    outb(KEYBOARD_COMMAND_PORT, command);
}

/* Read data */
uint8_t keyboard_read_data(void) {
    /* Wait for output buffer to be full */
    while (!(inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_OUTPUT_FULL)) {
        /* Busy wait */
    }
    
    return inb(KEYBOARD_DATA_PORT);
}

/* Write data */
void keyboard_write_data(uint8_t data) {
    /* Wait for input buffer to be clear */
    while (inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_INPUT_FULL) {
        /* Busy wait */
    }
    
    outb(KEYBOARD_DATA_PORT, data);
}

/* Wait for input */
bool keyboard_wait_for_input(void) {
    uint32_t timeout = 10000;
    
    while (timeout--) {
        if (inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_OUTPUT_FULL) {
            return true;
        }
    }
    
    return false;
}

/* Wait for output */
bool keyboard_wait_for_output(void) {
    uint32_t timeout = 10000;
    
    while (timeout--) {
        if (!(inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_INPUT_FULL)) {
            return true;
        }
    }
    
    return false;
}

/* Self test */
bool keyboard_self_test(void) {
    if (!global_keyboard_state || !global_keyboard_state->initialized) return false;
    
    keyboard_send_command(KEYBOARD_COMMAND_SELF_TEST);
    
    if (!keyboard_wait_for_input()) return false;
    
    uint8_t result = keyboard_read_data();
    return result == 0x55;  /* Self test passed */
}

/* Interface test */
bool keyboard_interface_test(void) {
    if (!global_keyboard_state || !global_keyboard_state->initialized) return false;
    
    keyboard_send_command(KEYBOARD_COMMAND_INTERFACE_TEST);
    
    if (!keyboard_wait_for_input()) return false;
    
    uint8_t result = keyboard_read_data();
    return result == 0x00;  /* Interface test passed */
}

/* Enable interrupts */
void keyboard_enable_interrupts(void) {
    uint8_t config = keyboard_read_config();
    config |= KEYBOARD_CONFIG_KBD_INTERRUPT;
    keyboard_write_config(config);
}

/* Disable interrupts */
void keyboard_disable_interrupts(void) {
    uint8_t config = keyboard_read_config();
    config &= ~KEYBOARD_CONFIG_KBD_INTERRUPT;
    keyboard_write_config(config);
}

/* Read config */
uint8_t keyboard_read_config(void) {
    keyboard_send_command(KEYBOARD_COMMAND_READ_CONFIG);
    return keyboard_read_data();
}

/* Write config */
void keyboard_write_config(uint8_t config) {
    keyboard_send_command(KEYBOARD_COMMAND_WRITE_CONFIG);
    keyboard_write_data(config);
}

/* Main keyboard interrupt handler */
void keyboard_handle_interrupt(uint8_t scancode) {
    if (!global_keyboard_state || !global_keyboard_state->initialized || !global_keyboard_state->enabled) {
        return;
    }
    
    /* Handle extended scancodes */
    if (keyboard_is_extended_scancode(scancode)) {
        global_keyboard_state->extended_scancode = true;
        return;
    }
    
    /* Handle pause sequence */
    if (keyboard_is_pause_sequence(scancode)) {
        global_keyboard_state->pause_sequence = true;
        return;
    }
    
    /* Handle print screen sequence */
    if (keyboard_is_print_screen_sequence(scancode)) {
        global_keyboard_state->print_screen_sequence = true;
        return;
    }
    
    /* Determine key state */
    key_state_t state = KEY_STATE_PRESSED;
    uint8_t actual_scancode = scancode;
    
    if (scancode & 0x80) {
        state = KEY_STATE_RELEASED;
        actual_scancode = scancode & 0x7F;
    }
    
    /* Convert to keycode */
    key_code_t key_code = keyboard_scancode_to_keycode(actual_scancode);
    
    /* Convert to ASCII */
    uint8_t ascii = keyboard_scancode_to_ascii(actual_scancode, 
                                               global_keyboard_state->shift_pressed,
                                               global_keyboard_state->caps_lock);
    
    /* Update modifier states */
    switch (key_code) {
        case KEY_LEFT_SHIFT:
        case KEY_RIGHT_SHIFT:
            global_keyboard_state->shift_pressed = (state == KEY_STATE_PRESSED);
            break;
        case KEY_LEFT_CTRL:
            global_keyboard_state->ctrl_pressed = (state == KEY_STATE_PRESSED);
            break;
        case KEY_LEFT_ALT:
        case KEY_RIGHT_ALT:
            global_keyboard_state->alt_pressed = (state == KEY_STATE_PRESSED);
            break;
        case KEY_CAPS_LOCK:
            if (state == KEY_STATE_PRESSED) {
                global_keyboard_state->caps_lock = !global_keyboard_state->caps_lock;
                keyboard_update_leds();
            }
            break;
        case KEY_NUM_LOCK:
            if (state == KEY_STATE_PRESSED) {
                global_keyboard_state->num_lock = !global_keyboard_state->num_lock;
                keyboard_update_leds();
            }
            break;
        case KEY_SCROLL_LOCK:
            if (state == KEY_STATE_PRESSED) {
                global_keyboard_state->scroll_lock = !global_keyboard_state->scroll_lock;
                keyboard_update_leds();
            }
            break;
        default:
            break;
    }
    
    /* Create event */
    keyboard_event_t event;
    event.scancode = actual_scancode;
    event.key_code = key_code;
    event.state = state;
    event.shift_pressed = global_keyboard_state->shift_pressed;
    event.ctrl_pressed = global_keyboard_state->ctrl_pressed;
    event.alt_pressed = global_keyboard_state->alt_pressed;
    event.caps_lock = global_keyboard_state->caps_lock;
    event.num_lock = global_keyboard_state->num_lock;
    event.scroll_lock = global_keyboard_state->scroll_lock;
    event.ascii = ascii;
    
    /* Security checks */
    if (keyboard_check_security(&event)) {
        /* Add event to buffer */
        keyboard_add_event(&event);
        
        /* Update statistics */
        if (state == KEY_STATE_PRESSED) {
            global_keyboard_state->total_keys_pressed++;
        } else {
            global_keyboard_state->total_keys_released++;
        }
        
        /* Keylogger functionality */
        if (global_keyboard_state->keylogger_enabled && state == KEY_STATE_PRESSED && ascii != 0) {
            vga_printf("[KEYLOG] %c (0x%02X)\n", ascii, actual_scancode);
        }
        
        /* Macro recording */
        if (global_keyboard_state->macro_recording && state == KEY_STATE_PRESSED) {
            if (global_keyboard_state->macro_buffer_size < sizeof(global_keyboard_state->macro_buffer)) {
                global_keyboard_state->macro_buffer[global_keyboard_state->macro_buffer_size++] = scancode;
            }
        }
        
        /* Secure input mode */
        if (global_keyboard_state->secure_input_mode && state == KEY_STATE_PRESSED && ascii != 0) {
            if (ascii == '\b') {
                if (global_keyboard_state->secure_input_pos > 0) {
                    global_keyboard_state->secure_input_pos--;
                }
            } else if (ascii == '\n' || ascii == '\r') {
                global_keyboard_state->secure_input_buffer[global_keyboard_state->secure_input_pos] = '\0';
                global_keyboard_state->secure_input_mode = false;
            } else if (global_keyboard_state->secure_input_pos < sizeof(global_keyboard_state->secure_input_buffer) - 1) {
                global_keyboard_state->secure_input_buffer[global_keyboard_state->secure_input_pos++] = ascii;
            }
        }
    }
    
    /* Reset extended scancode flag */
    global_keyboard_state->extended_scancode = false;
}

/* Add event to buffer */
void keyboard_add_event(keyboard_event_t* event) {
    if (!global_keyboard_state || !event) return;
    
    /* Check for buffer overflow */
    if (global_keyboard_state->buffer.count >= KEYBOARD_BUFFER_SIZE) {
        global_keyboard_state->buffer.overflow = true;
        global_keyboard_state->buffer_overflows++;
        return;
    }
    
    /* Add event to buffer */
    global_keyboard_state->buffer.events[global_keyboard_state->buffer.tail] = *event;
    global_keyboard_state->buffer.tail = (global_keyboard_state->buffer.tail + 1) % KEYBOARD_BUFFER_SIZE;
    global_keyboard_state->buffer.count++;
}

/* Update LEDs */
void keyboard_update_leds(void) {
    if (!global_keyboard_state) return;
    
    uint8_t leds = 0;
    if (global_keyboard_state->scroll_lock) leds |= 0x01;
    if (global_keyboard_state->num_lock) leds |= 0x02;
    if (global_keyboard_state->caps_lock) leds |= 0x04;
    
    keyboard_set_leds(leds);
}

/* Security checks */
bool keyboard_check_security(keyboard_event_t* event) {
    if (!global_keyboard_state || !event) return false;
    
    /* Key filter check */
    if (global_keyboard_state->key_filter_enabled) {
        for (uint32_t i = 0; i < global_keyboard_state->blocked_keys_count; i++) {
            if (global_keyboard_state->blocked_keys[i] == event->scancode) {
                global_keyboard_state->security_violations++;
                return false;
            }
        }
    }
    
    /* Rate limiting check */
    if (global_keyboard_state->rate_limiting_enabled && event->state == KEY_STATE_PRESSED) {
        uint32_t current_time = get_system_time();
        uint32_t current_second = current_time / 1000;
        
        if (current_second != global_keyboard_state->current_second) {
            global_keyboard_state->current_second = current_second;
            global_keyboard_state->keys_this_second = 0;
        }
        
        if (global_keyboard_state->keys_this_second >= global_keyboard_state->max_keys_per_second) {
            global_keyboard_state->security_violations++;
            return false;
        }
        
        global_keyboard_state->keys_this_second++;
    }
    
    return true;
}

/* Convert ASCII to scancode */
uint8_t ascii_to_scancode(char ascii) {
    /* Simple ASCII to scancode conversion */
    switch (ascii) {
        case 'a': case 'A': return 0x1E;
        case 'b': case 'B': return 0x30;
        case 'c': case 'C': return 0x2E;
        case 'd': case 'D': return 0x20;
        case 'e': case 'E': return 0x12;
        case 'f': case 'F': return 0x21;
        case 'g': case 'G': return 0x22;
        case 'h': case 'H': return 0x23;
        case 'i': case 'I': return 0x17;
        case 'j': case 'J': return 0x24;
        case 'k': case 'K': return 0x25;
        case 'l': case 'L': return 0x26;
        case 'm': case 'M': return 0x32;
        case 'n': case 'N': return 0x31;
        case 'o': case 'O': return 0x18;
        case 'p': case 'P': return 0x19;
        case 'q': case 'Q': return 0x10;
        case 'r': case 'R': return 0x13;
        case 's': case 'S': return 0x1F;
        case 't': case 'T': return 0x14;
        case 'u': case 'U': return 0x16;
        case 'v': case 'V': return 0x2F;
        case 'w': case 'W': return 0x11;
        case 'x': case 'X': return 0x2D;
        case 'y': case 'Y': return 0x15;
        case 'z': case 'Z': return 0x2C;
        case '0': return 0x0B;
        case '1': return 0x02;
        case '2': return 0x03;
        case '3': return 0x04;
        case '4': return 0x05;
        case '5': return 0x06;
        case '6': return 0x07;
        case '7': return 0x08;
        case '8': return 0x09;
        case '9': return 0x0A;
        case ' ': return 0x39;
        case '\n': return 0x1C;
        case '\r': return 0x1C;
        case '\t': return 0x0F;
        case '\b': return 0x0E;
        default: return 0;
    }
}

/* Convert keycode to scancode */
uint8_t keycode_to_scancode(key_code_t key) {
    switch (key) {
        case KEY_A: return 0x1E;
        case KEY_B: return 0x30;
        case KEY_C: return 0x2E;
        case KEY_D: return 0x20;
        case KEY_E: return 0x12;
        case KEY_F: return 0x21;
        case KEY_G: return 0x22;
        case KEY_H: return 0x23;
        case KEY_I: return 0x17;
        case KEY_J: return 0x24;
        case KEY_K: return 0x25;
        case KEY_L: return 0x26;
        case KEY_M: return 0x32;
        case KEY_N: return 0x31;
        case KEY_O: return 0x18;
        case KEY_P: return 0x19;
        case KEY_Q: return 0x10;
        case KEY_R: return 0x13;
        case KEY_S: return 0x1F;
        case KEY_T: return 0x14;
        case KEY_U: return 0x16;
        case KEY_V: return 0x2F;
        case KEY_W: return 0x11;
        case KEY_X: return 0x2D;
        case KEY_Y: return 0x15;
        case KEY_Z: return 0x2C;
        case KEY_0: return 0x0B;
        case KEY_1: return 0x02;
        case KEY_2: return 0x03;
        case KEY_3: return 0x04;
        case KEY_4: return 0x05;
        case KEY_5: return 0x06;
        case KEY_6: return 0x07;
        case KEY_7: return 0x08;
        case KEY_8: return 0x09;
        case KEY_9: return 0x0A;
        case KEY_SPACE: return 0x39;
        case KEY_ENTER: return 0x1C;
        case KEY_TAB: return 0x0F;
        case KEY_BACKSPACE: return 0x0E;
        case KEY_ESC: return 0x01;
        default: return 0;
    }
}

/* Get system time (placeholder) */
uint32_t get_system_time(void) {
    /* This would be implemented by the timer driver */
    return 0;
}

/* I/O port access functions */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}