#include "string.h"

/* String length */
size_t strlen(const char* str) {
    if (str == NULL) {
        return 0;
    }
    
    size_t length = 0;
    while (str[length] != '\0') {
        length++;
    }
    return length;
}

/* String copy */
char* strcpy(char* dest, const char* src) {
    if (dest == NULL || src == NULL) {
        return dest;
    }
    
    size_t i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    return dest;
}

/* String copy with length limit */
char* strncpy(char* dest, const char* src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }
    
    size_t i = 0;
    while (i < n && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    
    /* Pad with null bytes if necessary */
    while (i < n) {
        dest[i] = '\0';
        i++;
    }
    
    return dest;
}

/* String concatenation */
char* strcat(char* dest, const char* src) {
    if (dest == NULL || src == NULL) {
        return dest;
    }
    
    size_t dest_len = strlen(dest);
    size_t i = 0;
    
    while (src[i] != '\0') {
        dest[dest_len + i] = src[i];
        i++;
    }
    
    dest[dest_len + i] = '\0';
    return dest;
}

/* String concatenation with length limit */
char* strncat(char* dest, const char* src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }
    
    size_t dest_len = strlen(dest);
    size_t i = 0;
    
    while (i < n && src[i] != '\0') {
        dest[dest_len + i] = src[i];
        i++;
    }
    
    dest[dest_len + i] = '\0';
    return dest;
}

/* String comparison */
int strcmp(const char* str1, const char* str2) {
    if (str1 == NULL && str2 == NULL) {
        return 0;
    }
    if (str1 == NULL) {
        return -1;
    }
    if (str2 == NULL) {
        return 1;
    }
    
    size_t i = 0;
    while (str1[i] != '\0' && str2[i] != '\0') {
        if (str1[i] != str2[i]) {
            return (unsigned char)str1[i] - (unsigned char)str2[i];
        }
        i++;
    }
    
    return (unsigned char)str1[i] - (unsigned char)str2[i];
}

/* String comparison with length limit */
int strncmp(const char* str1, const char* str2, size_t n) {
    if (str1 == NULL && str2 == NULL) {
        return 0;
    }
    if (str1 == NULL) {
        return -1;
    }
    if (str2 == NULL) {
        return 1;
    }
    if (n == 0) {
        return 0;
    }
    
    size_t i = 0;
    while (i < n && str1[i] != '\0' && str2[i] != '\0') {
        if (str1[i] != str2[i]) {
            return (unsigned char)str1[i] - (unsigned char)str2[i];
        }
        i++;
    }
    
    if (i == n) {
        return 0;
    }
    
    return (unsigned char)str1[i] - (unsigned char)str2[i];
}

/* Find character in string */
char* strchr(const char* str, int c) {
    if (str == NULL) {
        return NULL;
    }
    
    size_t i = 0;
    while (str[i] != '\0') {
        if (str[i] == (char)c) {
            return (char*)(str + i);
        }
        i++;
    }
    
    /* Check for null terminator */
    if (c == '\0') {
        return (char*)(str + i);
    }
    
    return NULL;
}

/* Find character in string (reverse) */
char* strrchr(const char* str, int c) {
    if (str == NULL) {
        return NULL;
    }
    
    const char* last_occurrence = NULL;
    size_t i = 0;
    
    while (str[i] != '\0') {
        if (str[i] == (char)c) {
            last_occurrence = str + i;
        }
        i++;
    }
    
    /* Check for null terminator */
    if (c == '\0') {
        return (char*)(str + i);
    }
    
    return (char*)last_occurrence;
}

/* Find substring */
char* strstr(const char* haystack, const char* needle) {
    if (haystack == NULL || needle == NULL) {
        return NULL;
    }
    
    if (needle[0] == '\0') {
        return (char*)haystack;
    }
    
    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);
    
    if (needle_len > haystack_len) {
        return NULL;
    }
    
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        bool found = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return (char*)(haystack + i);
        }
    }
    
    return NULL;
}

/* Memory set */
void* memset(void* dest, int value, size_t n) {
    if (dest == NULL || n == 0) {
        return dest;
    }
    
    uint8_t* bytes = (uint8_t*)dest;
    uint8_t byte_value = (uint8_t)value;
    
    for (size_t i = 0; i < n; i++) {
        bytes[i] = byte_value;
    }
    
    return dest;
}

/* Memory copy */
void* memcpy(void* dest, const void* src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }
    
    uint8_t* dest_bytes = (uint8_t*)dest;
    const uint8_t* src_bytes = (const uint8_t*)src;
    
    for (size_t i = 0; i < n; i++) {
        dest_bytes[i] = src_bytes[i];
    }
    
    return dest;
}

/* Memory move (handles overlapping memory) */
void* memmove(void* dest, const void* src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }
    
    uint8_t* dest_bytes = (uint8_t*)dest;
    const uint8_t* src_bytes = (const uint8_t*)src;
    
    if (dest_bytes < src_bytes || dest_bytes >= src_bytes + n) {
        /* No overlap, use memcpy */
        return memcpy(dest, src, n);
    } else {
        /* Overlap, copy backwards */
        for (size_t i = n; i > 0; i--) {
            dest_bytes[i - 1] = src_bytes[i - 1];
        }
        return dest;
    }
}

/* Memory compare */
int memcmp(const void* ptr1, const void* ptr2, size_t n) {
    if (ptr1 == NULL && ptr2 == NULL) {
        return 0;
    }
    if (ptr1 == NULL) {
        return -1;
    }
    if (ptr2 == NULL) {
        return 1;
    }
    if (n == 0) {
        return 0;
    }
    
    const uint8_t* bytes1 = (const uint8_t*)ptr1;
    const uint8_t* bytes2 = (const uint8_t*)ptr2;
    
    for (size_t i = 0; i < n; i++) {
        if (bytes1[i] != bytes2[i]) {
            return (int)bytes1[i] - (int)bytes2[i];
        }
    }
    
    return 0;
}

/* Find byte in memory */
void* memchr(const void* ptr, int value, size_t n) {
    if (ptr == NULL || n == 0) {
        return NULL;
    }
    
    const uint8_t* bytes = (const uint8_t*)ptr;
    uint8_t byte_value = (uint8_t)value;
    
    for (size_t i = 0; i < n; i++) {
        if (bytes[i] == byte_value) {
            return (void*)(bytes + i);
        }
    }
    
    return NULL;
}

/* Safe string copy with bounds checking */
size_t strlcpy(char* dest, const char* src, size_t size) {
    if (dest == NULL || src == NULL || size == 0) {
        return 0;
    }
    
    size_t src_len = strlen(src);
    
    if (size > 0) {
        size_t copy_len = (src_len < size - 1) ? src_len : size - 1;
        for (size_t i = 0; i < copy_len; i++) {
            dest[i] = src[i];
        }
        dest[copy_len] = '\0';
    }
    
    return src_len;
}

/* Safe string concatenation with bounds checking */
size_t strlcat(char* dest, const char* src, size_t size) {
    if (dest == NULL || src == NULL || size == 0) {
        return 0;
    }
    
    size_t dest_len = strlen(dest);
    size_t src_len = strlen(src);
    
    if (dest_len >= size) {
        return dest_len + src_len;
    }
    
    size_t remaining = size - dest_len - 1;
    size_t copy_len = (src_len < remaining) ? src_len : remaining;
    
    for (size_t i = 0; i < copy_len; i++) {
        dest[dest_len + i] = src[i];
    }
    
    dest[dest_len + copy_len] = '\0';
    
    return dest_len + src_len;
}

/* Convert integer to string */
char* itoa(int value, char* str, int base) {
    if (str == NULL || base < 2 || base > 36) {
        return str;
    }
    
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    int tmp_value;
    
    /* Handle negative numbers for base 10 */
    bool negative = false;
    if (value < 0 && base == 10) {
        negative = true;
        value = -value;
    }
    
    /* Convert number */
    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[tmp_value - value * base];
    } while (value);
    
    /* Add negative sign for base 10 */
    if (negative) {
        *ptr++ = '-';
    }
    
    *ptr-- = '\0';
    
    /* Reverse string */
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    
    return str;
}

/* Convert unsigned integer to string */
char* utoa(unsigned int value, char* str, int base) {
    if (str == NULL || base < 2 || base > 36) {
        return str;
    }
    
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    unsigned int tmp_value;
    
    /* Convert number */
    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[tmp_value - value * base];
    } while (value);
    
    *ptr-- = '\0';
    
    /* Reverse string */
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    
    return str;
}

/* Convert long integer to string */
char* ltoa(long value, char* str, int base) {
    return itoa((int)value, str, base);
}

/* Convert unsigned long integer to string */
char* ultoa(unsigned long value, char* str, int base) {
    return utoa((unsigned int)value, str, base);
}

/* Convert long long integer to string */
char* lltoa(long long value, char* str, int base) {
    if (str == NULL || base < 2 || base > 36) {
        return str;
    }
    
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    long long tmp_value;
    
    /* Handle negative numbers for base 10 */
    bool negative = false;
    if (value < 0 && base == 10) {
        negative = true;
        value = -value;
    }
    
    /* Convert number */
    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[tmp_value - value * base];
    } while (value);
    
    /* Add negative sign for base 10 */
    if (negative) {
        *ptr++ = '-';
    }
    
    *ptr-- = '\0';
    
    /* Reverse string */
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    
    return str;
}

/* Convert unsigned long long integer to string */
char* ulltoa(unsigned long long value, char* str, int base) {
    if (str == NULL || base < 2 || base > 36) {
        return str;
    }
    
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    unsigned long long tmp_value;
    
    /* Convert number */
    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[tmp_value - value * base];
    } while (value);
    
    *ptr-- = '\0';
    
    /* Reverse string */
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    
    return str;
}

/* Convert string to integer */
int atoi(const char* str) {
    if (str == NULL) {
        return 0;
    }
    
    int result = 0;
    int sign = 1;
    size_t i = 0;
    
    /* Skip whitespace */
    while (str[i] == ' ' || str[i] == '\t') {
        i++;
    }
    
    /* Handle sign */
    if (str[i] == '-') {
        sign = -1;
        i++;
    } else if (str[i] == '+') {
        i++;
    }
    
    /* Convert digits */
    while (str[i] >= '0' && str[i] <= '9') {
        result = result * 10 + (str[i] - '0');
        i++;
    }
    
    return result * sign;
}

/* Convert string to long integer */
long atol(const char* str) {
    return (long)atoi(str);
}

/* Convert string to long long integer */
long long atoll(const char* str) {
    if (str == NULL) {
        return 0;
    }
    
    long long result = 0;
    int sign = 1;
    size_t i = 0;
    
    /* Skip whitespace */
    while (str[i] == ' ' || str[i] == '\t') {
        i++;
    }
    
    /* Handle sign */
    if (str[i] == '-') {
        sign = -1;
        i++;
    } else if (str[i] == '+') {
        i++;
    }
    
    /* Convert digits */
    while (str[i] >= '0' && str[i] <= '9') {
        result = result * 10 + (str[i] - '0');
        i++;
    }
    
    return result * sign;
}

/* Convert string to unsigned integer */
unsigned int strtou(const char* str, char** endptr, int base) {
    if (str == NULL) {
        if (endptr != NULL) {
            *endptr = NULL;
        }
        return 0;
    }
    
    unsigned int result = 0;
    size_t i = 0;
    
    /* Skip whitespace */
    while (str[i] == ' ' || str[i] == '\t') {
        i++;
    }
    
    /* Handle sign */
    if (str[i] == '+') {
        i++;
    }
    
    /* Handle base prefix */
    if (base == 0) {
        if (str[i] == '0') {
            if (str[i + 1] == 'x' || str[i + 1] == 'X') {
                base = 16;
                i += 2;
            } else {
                base = 8;
                i++;
            }
        } else {
            base = 10;
        }
    }
    
    /* Convert digits */
    while (1) {
        int digit;
        
        if (str[i] >= '0' && str[i] <= '9') {
            digit = str[i] - '0';
        } else if (str[i] >= 'A' && str[i] <= 'Z') {
            digit = str[i] - 'A' + 10;
        } else if (str[i] >= 'a' && str[i] <= 'z') {
            digit = str[i] - 'a' + 10;
        } else {
            break;
        }
        
        if (digit >= base) {
            break;
        }
        
        result = result * base + digit;
        i++;
    }
    
    if (endptr != NULL) {
        *endptr = (char*)(str + i);
    }
    
    return result;
}

/* Convert string to unsigned long integer */
unsigned long strtoul(const char* str, char** endptr, int base) {
    return (unsigned long)strtou(str, endptr, base);
}

/* Convert string to unsigned long long integer */
unsigned long long strtoull(const char* str, char** endptr, int base) {
    return (unsigned long long)strtou(str, endptr, base);
}

/* Safe string formatting */
int snprintf(char* str, size_t size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vsnprintf(str, size, format, args);
    va_end(args);
    return result;
}

/* Safe string formatting with va_list */
int vsnprintf(char* str, size_t size, const char* format, va_list args) {
    if (str == NULL || size == 0 || format == NULL) {
        return 0;
    }
    
    size_t written = 0;
    size_t i = 0;
    
    while (format[i] != '\0' && written < size - 1) {
        if (format[i] != '%') {
            str[written++] = format[i++];
            continue;
        }
        
        /* Handle format specifier */
        i++; /* Skip '%' */
        
        if (format[i] == '\0') {
            break;
        }
        
        switch (format[i]) {
            case 'd':
            case 'i': {
                int value = va_arg(args, int);
                char buffer[32];
                itoa(value, buffer, 10);
                size_t len = strlen(buffer);
                if (written + len < size - 1) {
                    strcpy(str + written, buffer);
                    written += len;
                }
                break;
            }
            
            case 'u': {
                unsigned int value = va_arg(args, unsigned int);
                char buffer[32];
                utoa(value, buffer, 10);
                size_t len = strlen(buffer);
                if (written + len < size - 1) {
                    strcpy(str + written, buffer);
                    written += len;
                }
                break;
            }
            
            case 'x':
            case 'X': {
                unsigned int value = va_arg(args, unsigned int);
                char buffer[32];
                utoa(value, buffer, 16);
                size_t len = strlen(buffer);
                if (written + len < size - 1) {
                    strcpy(str + written, buffer);
                    written += len;
                }
                break;
            }
            
            case 'p': {
                uintptr_t value = va_arg(args, uintptr_t);
                char buffer[32];
                utoa(value, buffer, 16);
                size_t len = strlen(buffer);
                if (written + len < size - 1) {
                    str[written++] = '0';
                    str[written++] = 'x';
                    strcpy(str + written, buffer);
                    written += len;
                }
                break;
            }
            
            case 's': {
                const char* value = va_arg(args, const char*);
                if (value == NULL) {
                    value = "(null)";
                }
                size_t len = strlen(value);
                if (written + len < size - 1) {
                    strcpy(str + written, value);
                    written += len;
                }
                break;
            }
            
            case 'c': {
                int value = va_arg(args, int);
                if (written < size - 1) {
                    str[written++] = (char)value;
                }
                break;
            }
            
            case '%': {
                if (written < size - 1) {
                    str[written++] = '%';
                }
                break;
            }
            
            default:
                /* Unknown format specifier, just copy it */
                if (written < size - 1) {
                    str[written++] = '%';
                }
                if (written < size - 1) {
                    str[written++] = format[i];
                }
                break;
        }
        
        i++;
    }
    
    str[written] = '\0';
    return written;
}

/* String tokenization */
char* strtok(char* str, const char* delim) {
    static char* saveptr = NULL;
    return strtok_r(str, delim, &saveptr);
}

/* Reentrant string tokenization */
char* strtok_r(char* str, const char* delim, char** saveptr) {
    if (delim == NULL || saveptr == NULL) {
        return NULL;
    }
    
    char* token;
    
    if (str == NULL) {
        str = *saveptr;
    }
    
    if (str == NULL) {
        return NULL;
    }
    
    /* Skip leading delimiters */
    str += strspn(str, delim);
    
    if (*str == '\0') {
        *saveptr = NULL;
        return NULL;
    }
    
    /* Find end of token */
    token = str;
    str = strpbrk(str, delim);
    
    if (str == NULL) {
        *saveptr = NULL;
    } else {
        *str = '\0';
        *saveptr = str + 1;
    }
    
    return token;
}

/* Find span of characters in string */
size_t strspn(const char* str, const char* accept) {
    if (str == NULL || accept == NULL) {
        return 0;
    }
    
    size_t count = 0;
    
    while (str[count] != '\0') {
        bool found = false;
        for (size_t i = 0; accept[i] != '\0'; i++) {
            if (str[count] == accept[i]) {
                found = true;
                break;
            }
        }
        if (!found) {
            break;
        }
        count++;
    }
    
    return count;
}

/* Find span of characters not in string */
size_t strcspn(const char* str, const char* reject) {
    if (str == NULL || reject == NULL) {
        return 0;
    }
    
    size_t count = 0;
    
    while (str[count] != '\0') {
        bool found = false;
        for (size_t i = 0; reject[i] != '\0'; i++) {
            if (str[count] == reject[i]) {
                found = true;
                break;
            }
        }
        if (found) {
            break;
        }
        count++;
    }
    
    return count;
}

/* Find character in string from set */
char* strpbrk(const char* str, const char* accept) {
    if (str == NULL || accept == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; str[i] != '\0'; i++) {
        for (size_t j = 0; accept[j] != '\0'; j++) {
            if (str[i] == accept[j]) {
                return (char*)(str + i);
            }
        }
    }
    
    return NULL;
}

/* Duplicate string */
char* strdup(const char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    size_t len = strlen(str) + 1;
    char* copy = kmalloc(len);
    if (copy == NULL) {
        return NULL;
    }
    
    return strcpy(copy, str);
}

/* Case-insensitive string comparison */
int strcasecmp(const char* str1, const char* str2) {
    if (str1 == NULL && str2 == NULL) {
        return 0;
    }
    if (str1 == NULL) {
        return -1;
    }
    if (str2 == NULL) {
        return 1;
    }
    
    size_t i = 0;
    while (str1[i] != '\0' && str2[i] != '\0') {
        char c1 = str1[i];
        char c2 = str2[i];
        
        /* Convert to lowercase */
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += 'a' - 'A';
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += 'a' - 'A';
        }
        
        if (c1 != c2) {
            return (unsigned char)c1 - (unsigned char)c2;
        }
        i++;
    }
    
    char c1 = str1[i];
    char c2 = str2[i];
    
    /* Convert to lowercase */
    if (c1 >= 'A' && c1 <= 'Z') {
        c1 += 'a' - 'A';
    }
    if (c2 >= 'A' && c2 <= 'Z') {
        c2 += 'a' - 'A';
    }
    
    return (unsigned char)c1 - (unsigned char)c2;
}

/* Case-insensitive string comparison with length limit */
int strncasecmp(const char* str1, const char* str2, size_t n) {
    if (str1 == NULL && str2 == NULL) {
        return 0;
    }
    if (str1 == NULL) {
        return -1;
    }
    if (str2 == NULL) {
        return 1;
    }
    if (n == 0) {
        return 0;
    }
    
    size_t i = 0;
    while (i < n && str1[i] != '\0' && str2[i] != '\0') {
        char c1 = str1[i];
        char c2 = str2[i];
        
        /* Convert to lowercase */
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += 'a' - 'A';
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += 'a' - 'A';
        }
        
        if (c1 != c2) {
            return (unsigned char)c1 - (unsigned char)c2;
        }
        i++;
    }
    
    if (i == n) {
        return 0;
    }
    
    char c1 = str1[i];
    char c2 = str2[i];
    
    /* Convert to lowercase */
    if (c1 >= 'A' && c1 <= 'Z') {
        c1 += 'a' - 'A';
    }
    if (c2 >= 'A' && c2 <= 'Z') {
        c2 += 'a' - 'A';
    }
    
    return (unsigned char)c1 - (unsigned char)c2;
}

/* Convert character to lowercase */
int tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

/* Convert character to uppercase */
int toupper(int c) {
    if (c >= 'a' && c <= 'z') {
        return c - ('a' - 'A');
    }
    return c;
}

/* Check if character is alphanumeric */
int isalnum(int c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* Check if character is alphabetic */
int isalpha(int c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* Check if character is digit */
int isdigit(int c) {
    return c >= '0' && c <= '9';
}

/* Check if character is lowercase */
int islower(int c) {
    return c >= 'a' && c <= 'z';
}

/* Check if character is uppercase */
int isupper(int c) {
    return c >= 'A' && c <= 'Z';
}

/* Check if character is whitespace */
int isspace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* Check if character is printable */
int isprint(int c) {
    return c >= 32 && c <= 126;
}

/* Check if character is control character */
int iscntrl(int c) {
    return (c >= 0 && c <= 31) || c == 127;
}

/* Check if character is punctuation */
int ispunct(int c) {
    return (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || 
           (c >= 91 && c <= 96) || (c >= 123 && c <= 126);
}

/* Check if character is hexadecimal digit */
int isxdigit(int c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

/* Convert string to lowercase */
char* strlwr(char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; str[i] != '\0'; i++) {
        str[i] = tolower(str[i]);
    }
    
    return str;
}

/* Convert string to uppercase */
char* strupr(char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; str[i] != '\0'; i++) {
        str[i] = toupper(str[i]);
    }
    
    return str;
}

/* Get string length (safe version) */
size_t strnlen(const char* str, size_t maxlen) {
    if (str == NULL) {
        return 0;
    }
    
    size_t length = 0;
    while (length < maxlen && str[length] != '\0') {
        length++;
    }
    
    return length;
}

/* Memory copy with overlap detection */
void* memccpy(void* dest, const void* src, int c, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return NULL;
    }
    
    uint8_t* dest_bytes = (uint8_t*)dest;
    const uint8_t* src_bytes = (const uint8_t*)src;
    uint8_t byte_value = (uint8_t)c;
    
    for (size_t i = 0; i < n; i++) {
        dest_bytes[i] = src_bytes[i];
        if (src_bytes[i] == byte_value) {
            return dest + i + 1;
        }
    }
    
    return NULL;
}

/* Memory set with pattern */
void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (haystack == NULL || needle == NULL || haystacklen == 0 || needlelen == 0) {
        return NULL;
    }
    
    if (needlelen > haystacklen) {
        return NULL;
    }
    
    const uint8_t* haystack_bytes = (const uint8_t*)haystack;
    const uint8_t* needle_bytes = (const uint8_t*)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        bool found = true;
        for (size_t j = 0; j < needlelen; j++) {
            if (haystack_bytes[i + j] != needle_bytes[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return (void*)(haystack_bytes + i);
        }
    }
    
    return NULL;
}