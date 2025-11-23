#ifndef STDBOOL_H
#define STDBOOL_H

/* Boolean type and constants for kernel */

/* Boolean type */
#define bool _Bool

/* Boolean constants */
#define true 1
#define false 0

/* Boolean macros */
#define __bool_true_false_are_defined 1

/* Boolean type definition */
typedef _Bool bool;

/* Boolean conversion macros */
#define bool_to_int(b) ((b) ? 1 : 0)
#define int_to_bool(i) ((i) != 0)

/* Boolean operations */
#define bool_and(a, b) ((a) && (b))
#define bool_or(a, b) ((a) || (b))
#define bool_not(a) (!(a))
#define bool_xor(a, b) ((a) != (b))

/* Boolean validation */
#define bool_is_valid(b) ((b) == true || (b) == false)
#define bool_assert(b) ((b) == true || (b) == false)

/* Boolean to string conversion */
#define bool_to_str(b) ((b) ? "true" : "false")

/* Common boolean functions */
static inline bool bool_from_int(int value) {
    return value != 0;
}

static inline int bool_to_int(bool value) {
    return value ? 1 : 0;
}

static inline bool bool_and_func(bool a, bool b) {
    return a && b;
}

static inline bool bool_or_func(bool a, bool b) {
    return a || b;
}

static inline bool bool_not_func(bool a) {
    return !a;
}

static inline bool bool_xor_func(bool a, bool b) {
    return a != b;
}

/* Boolean array operations */
static inline bool bool_array_all(const bool* array, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (!array[i]) return false;
    }
    return true;
}

static inline bool bool_array_any(const bool* array, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (array[i]) return true;
    }
    return false;
}

static inline size_t bool_array_count(const bool* array, size_t size) {
    size_t count = 0;
    for (size_t i = 0; i < size; i++) {
        if (array[i]) count++;
    }
    return count;
}

/* Boolean validation functions */
static inline bool bool_is_true(bool value) {
    return value == true;
}

static inline bool bool_is_false(bool value) {
    return value == false;
}

static inline bool bool_is_valid(bool value) {
    return value == true || value == false;
}

/* Boolean conversion functions */
static inline const char* bool_to_string(bool value) {
    return value ? "true" : "false";
}

static inline char bool_to_char(bool value) {
    return value ? 'T' : 'F';
}

static inline int bool_to_int_safe(bool value) {
    return value ? 1 : 0;
}

/* Boolean arithmetic */
static inline bool bool_add(bool a, bool b) {
    return a || b;
}

static inline bool bool_multiply(bool a, bool b) {
    return a && b;
}

/* Boolean comparison */
static inline bool bool_equal(bool a, bool b) {
    return a == b;
}

static inline bool bool_not_equal(bool a, bool b) {
    return a != b;
}

/* Boolean logical operations */
static inline bool bool_implies(bool a, bool b) {
    return !a || b;
}

static inline bool bool_equivalent(bool a, bool b) {
    return a == b;
}

/* Boolean set operations */
static inline bool bool_union(bool a, bool b) {
    return a || b;
}

static inline bool bool_intersection(bool a, bool b) {
    return a && b;
}

static inline bool bool_difference(bool a, bool b) {
    return a && !b;
}

static inline bool bool_complement(bool a) {
    return !a;
}

/* Boolean conditional operations */
static inline int bool_conditional(bool condition, int true_val, int false_val) {
    return condition ? true_val : false_val;
}

static inline const char* bool_conditional_str(bool condition, const char* true_str, const char* false_str) {
    return condition ? true_str : false_str;
}

/* Boolean state management */
typedef struct {
    bool value;
    bool previous;
    bool changed;
} bool_state_t;

static inline void bool_state_init(bool_state_t* state, bool initial) {
    state->value = initial;
    state->previous = initial;
    state->changed = false;
}

static inline void bool_state_update(bool_state_t* state, bool new_value) {
    state->previous = state->value;
    state->value = new_value;
    state->changed = (state->value != state->previous);
}

static inline bool bool_state_changed(bool_state_t* state) {
    return state->changed;
}

static inline bool bool_state_rising_edge(bool_state_t* state) {
    return state->changed && state->value;
}

static inline bool bool_state_falling_edge(bool_state_t* state) {
    return state->changed && !state->value;
}

/* Boolean validation macros */
#define BOOL_VALIDATE(value) \
    do { \
        if (!bool_is_valid(value)) { \
            return false; \
        } \
    } while (0)

#define BOOL_ASSERT(value) \
    do { \
        if (!bool_is_valid(value)) { \
            panic("Invalid boolean value"); \
        } \
    } while (0)

/* Boolean debugging */
#ifdef DEBUG
#define BOOL_DEBUG(value, name) \
    do { \
        debug("Boolean %s = %s", name, bool_to_string(value)); \
    } while (0)
#else
#define BOOL_DEBUG(value, name) do {} while (0)
#endif

/* Kernel-specific boolean extensions */
#define KERNEL_BOOL_TRUE true
#define KERNEL_BOOL_FALSE false
#define KERNEL_BOOL_ERROR false
#define KERNEL_BOOL_SUCCESS true

/* Boolean result types */
typedef enum {
    BOOL_RESULT_FALSE = 0,
    BOOL_RESULT_TRUE = 1,
    BOOL_RESULT_ERROR = -1
} bool_result_t;

/* Boolean state machine */
typedef enum {
    BOOL_STATE_FALSE = 0,
    BOOL_STATE_TRUE = 1,
    BOOL_STATE_UNKNOWN = 2
} bool_state_enum_t;

/* Common boolean patterns */
#define BOOL_PATTERN_TOGGLE(prev, curr) ((prev) != (curr))
#define BOOL_PATTERN_RISING_EDGE(prev, curr) (!(prev) && (curr))
#define BOOL_PATTERN_FALLING_EDGE(prev, curr) ((prev) && !(curr))
#define BOOL_PATTERN_STABLE(prev, curr) ((prev) == (curr))

#endif /* STDBOOL_H */