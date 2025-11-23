#ifndef STDARG_H
#define STDARG_H

/* Variable argument list handling for kernel */

typedef __builtin_va_list va_list;

/* Start variable argument list */
#define va_start(ap, param) __builtin_va_start(ap, param)

/* End variable argument list */
#define va_end(ap) __builtin_va_end(ap)

/* Get next argument */
#define va_arg(ap, type) __builtin_va_arg(ap, type)

/* Copy variable argument list */
#define va_copy(dest, src) __builtin_va_copy(dest, src)

/* GCC specific extensions */
#define __va_copy(dest, src) __builtin_va_copy(dest, src)

/* Variable argument macros for different types */
#define va_arg_int(ap) va_arg(ap, int)
#define va_arg_uint(ap) va_arg(ap, unsigned int)
#define va_arg_long(ap) va_arg(ap, long)
#define va_arg_ulong(ap) va_arg(ap, unsigned long)
#define va_arg_llong(ap) va_arg(ap, long long)
#define va_arg_ullong(ap) va_arg(ap, unsigned long long)
#define va_arg_ptr(ap, type) va_arg(ap, type*)
#define va_arg_str(ap) va_arg(ap, char*)
#define va_arg_bool(ap) va_arg(ap, int)
#define va_arg_size(ap) va_arg(ap, size_t)
#define va_arg_char(ap) va_arg(ap, int)

/* Helper macros for common patterns */
#define VA_LIST_START(ap, last) va_start(ap, last)
#define VA_LIST_END(ap) va_end(ap)
#define VA_LIST_COPY(dest, src) va_copy(dest, src)

/* Safe argument extraction with bounds checking */
#define VA_ARG_SAFE(ap, type, default_val) \
    ({ \
        type _val = default_val; \
        if (sizeof(type) <= sizeof(void*)) { \
            _val = va_arg(ap, type); \
        } \
        _val; \
    })

/* Variable argument list validation */
static inline bool va_list_valid(va_list* ap) {
    return ap != NULL;
}

static inline bool va_args_remaining(va_list* ap, int expected_count) {
    /* This is a best-effort check - actual implementation would be platform-specific */
    return ap != NULL && expected_count > 0;
}

/* Kernel-specific va_list extensions */
typedef struct {
    va_list args;
    char* buffer;
    size_t buffer_size;
    size_t buffer_pos;
} kernel_va_buffer_t;

/* Initialize va_buffer */
static inline void kernel_va_buffer_init(kernel_va_buffer_t* vab, char* buffer, size_t size) {
    vab->buffer = buffer;
    vab->buffer_size = size;
    vab->buffer_pos = 0;
    if (buffer != NULL && size > 0) {
        buffer[0] = '\0';
    }
}

/* Add string to va_buffer */
static inline void kernel_va_buffer_add(kernel_va_buffer_t* vab, const char* str) {
    if (vab->buffer == NULL || vab->buffer_pos >= vab->buffer_size - 1) {
        return;
    }
    
    size_t len = 0;
    while (str[len] != '\0' && vab->buffer_pos < vab->buffer_size - 1) {
        vab->buffer[vab->buffer_pos++] = str[len++];
    }
    vab->buffer[vab->buffer_pos] = '\0';
}

/* Format argument extraction */
static inline const char* va_arg_string(va_list* ap) {
    return va_arg(*ap, char*);
}

static inline int va_arg_int(va_list* ap) {
    return va_arg(*ap, int);
}

static inline unsigned int va_arg_uint(va_list* ap) {
    return va_arg(*ap, unsigned int);
}

static inline long va_arg_long(va_list* ap) {
    return va_arg(*ap, long);
}

static inline unsigned long va_arg_ulong(va_list* ap) {
    return va_arg(*ap, unsigned long);
}

static inline long long va_arg_llong(va_list* ap) {
    return va_arg(*ap, long long);
}

static inline unsigned long long va_arg_ullong(va_list* ap) {
    return va_arg(*ap, unsigned long long);
}

static inline void* va_arg_ptr(va_list* ap) {
    return va_arg(*ap, void*);
}

static inline size_t va_arg_size(va_list* ap) {
    return va_arg(*ap, size_t);
}

/* Safe argument extraction with type checking */
#define VA_ARG_CHECKED(ap, type, expected_type) \
    ({ \
        type _val = (type)0; \
        if (sizeof(type) == sizeof(expected_type)) { \
            _val = va_arg(ap, expected_type); \
        } \
        _val; \
    })

/* Standard va_list for kernel use */
#define KERNEL_VA_LIST va_list
#define KERNEL_VA_START va_start
#define KERNEL_VA_END va_end
#define KERNEL_VA_ARG va_arg
#define KERNEL_VA_COPY va_copy

#endif /* STDARG_H */