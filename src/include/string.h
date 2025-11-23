#ifndef STRING_H
#define STRING_H

#include "stddef.h"

/* String manipulation functions for kernel */

/* String length */
size_t strlen(const char* str);
size_t strnlen(const char* str, size_t maxlen);

/* String copy */
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
char* strcat(char* dest, const char* src);
char* strncat(char* dest, const char* src, size_t n);

/* String comparison */
int strcmp(const char* str1, const char* str2);
int strncmp(const char* str1, const char* str2, size_t n);
int strcasecmp(const char* str1, const char* str2);
int strncasecmp(const char* str1, const char* str2, size_t n);

/* String search */
char* strchr(const char* str, int c);
char* strrchr(const char* str, int c);
char* strstr(const char* haystack, const char* needle);
char* strcasestr(const char* haystack, const char* needle);
char* strtok(char* str, const char* delim);
char* strtok_r(char* str, const char* delim, char** saveptr);

/* String span */
size_t strspn(const char* str, const char* accept);
size_t strcspn(const char* str, const char* reject);
char* strpbrk(const char* str, const char* accept);

/* String duplication */
char* strdup(const char* str);
char* strndup(const char* str, size_t n);

/* Safe string functions */
size_t strlcpy(char* dest, const char* src, size_t size);
size_t strlcat(char* dest, const char* src, size_t size);

/* String formatting */
int snprintf(char* str, size_t size, const char* format, ...);
int vsnprintf(char* str, size_t size, const char* format, va_list ap);

/* String conversion */
int atoi(const char* str);
long atol(const char* str);
long long atoll(const char* str);
double atof(const char* str);

/* String to number conversion with error checking */
bool str_to_int(const char* str, int* value);
bool str_to_long(const char* str, long* value);
bool str_to_llong(const char* str, long long* value);
bool str_to_double(const char* str, double* value);

/* Number to string conversion */
char* itoa(int value, char* str, int base);
char* ltoa(long value, char* str, int base);
char* lltoa(long long value, char* str, int base);
char* utoa(unsigned int value, char* str, int base);
char* ultoa(unsigned long value, char* str, int base);
char* ulltoa(unsigned long long value, char* str, int base);

/* String validation */
bool str_is_empty(const char* str);
bool str_is_null_or_empty(const char* str);
bool str_is_whitespace(const char* str);
bool str_is_alphanumeric(const char* str);
bool str_is_alpha(const char* str);
bool str_is_digit(const char* str);
bool str_is_hex(const char* str);
bool str_is_printable(const char* str);

/* String manipulation */
char* str_trim_left(char* str);
char* str_trim_right(char* str);
char* str_trim(char* str);
char* str_to_upper(char* str);
char* str_to_lower(char* str);
char* str_reverse(char* str);
char* str_repeat(char* dest, const char* src, size_t count);

/* String comparison utilities */
bool str_equals(const char* str1, const char* str2);
bool str_equals_ignore_case(const char* str1, const char* str2);
bool str_starts_with(const char* str, const char* prefix);
bool str_ends_with(const char* str, const char* suffix);
bool str_contains(const char* str, const char* substring);
bool str_contains_ignore_case(const char* str, const char* substring);

/* String search utilities */
size_t str_find(const char* str, const char* substring);
size_t str_find_ignore_case(const char* str, const char* substring);
size_t str_find_char(const char* str, int c);
size_t str_find_last_char(const char* str, int c);
size_t str_count(const char* str, const char* substring);
size_t str_count_char(const char* str, int c);

/* String replacement */
char* str_replace(char* str, const char* old_str, const char* new_str);
char* str_replace_char(char* str, int old_char, int new_char);
char* str_replace_all(char* str, const char* old_str, const char* new_str);

/* String splitting */
typedef struct {
    char** tokens;
    size_t count;
    size_t capacity;
} string_array_t;

string_array_t* str_split(const char* str, const char* delimiter);
void str_array_free(string_array_t* array);
char* str_join(const char** strings, size_t count, const char* separator);

/* String formatting */
char* str_format(const char* format, ...);
char* str_vformat(const char* format, va_list ap);
char* str_append(char* dest, const char* src);
char* str_append_format(char* dest, const char* format, ...);

/* String padding */
char* str_pad_left(char* str, size_t width, char pad_char);
char* str_pad_right(char* str, size_t width, char pad_char);
char* str_pad_center(char* str, size_t width, char pad_char);

/* String truncation */
char* str_truncate(char* str, size_t max_length);
char* str_truncate_with_ellipsis(char* str, size_t max_length);

/* String width calculation */
size_t str_width(const char* str);
size_t str_display_width(const char* str);
bool str_is_wide_char(const char* str);

/* String encoding */
char* str_to_utf8(const char* str);
char* str_from_utf8(const char* str);
bool str_is_valid_utf8(const char* str);

/* String hashing */
u32 str_hash(const char* str);
u64 str_hash64(const char* str);
u32 str_hash_ignore_case(const char* str);
u64 str_hash64_ignore_case(const char* str);

/* String encryption/decryption */
char* str_encrypt(const char* str, const char* key);
char* str_decrypt(const char* str, const char* key);

/* String compression */
char* str_compress(const char* str);
char* str_decompress(const char* str);

/* String encoding/decoding */
char* str_base64_encode(const char* str);
char* str_base64_decode(const char* str);
char* str_url_encode(const char* str);
char* str_url_decode(const char* str);
char* str_html_encode(const char* str);
char* str_html_decode(const char* str);

/* String pattern matching */
bool str_match_pattern(const char* str, const char* pattern);
bool str_match_regex(const char* str, const char* regex);
bool str_match_wildcard(const char* str, const char* pattern);

/* String parsing */
bool str_parse_int(const char* str, int* value);
bool str_parse_long(const char* str, long* value);
bool str_parse_llong(const char* str, long long* value);
bool str_parse_uint(const char* str, unsigned int* value);
bool str_parse_ulong(const char* str, unsigned long* value);
bool str_parse_ullong(const char* str, unsigned long long* value);
bool str_parse_double(const char* str, double* value);

/* String validation */
bool str_validate_email(const char* str);
bool str_validate_ip(const char* str);
bool str_validate_url(const char* str);
bool str_validate_filename(const char* str);
bool str_validate_path(const char* str);

/* String memory operations */
char* str_memcpy(char* dest, const char* src, size_t n);
char* str_memmove(char* dest, const char* src, size_t n);
char* str_memset(char* str, int c, size_t n);
int str_memcmp(const char* str1, const char* str2, size_t n);
char* str_memchr(const char* str, int c, size_t n);

/* String buffer operations */
typedef struct {
    char* data;
    size_t size;
    size_t capacity;
    size_t position;
} string_buffer_t;

string_buffer_t* string_buffer_create(size_t initial_capacity);
void string_buffer_destroy(string_buffer_t* buffer);
int string_buffer_append(string_buffer_t* buffer, const char* str);
int string_buffer_append_char(string_buffer_t* buffer, char c);
int string_buffer_append_format(string_buffer_t* buffer, const char* format, ...);
const char* string_buffer_get_string(const string_buffer_t* buffer);
size_t string_buffer_get_length(const string_buffer_t* buffer);
void string_buffer_clear(string_buffer_t* buffer);
char* string_buffer_release(string_buffer_t* buffer);

/* String pool for memory efficiency */
typedef struct string_pool string_pool_t;

string_pool_t* string_pool_create(size_t initial_size);
void string_pool_destroy(string_pool_t* pool);
const char* string_pool_add(string_pool_t* pool, const char* str);
size_t string_pool_get_count(const string_pool_t* pool);
size_t string_pool_get_size(const string_pool_t* pool);

/* String interning */
typedef struct string_intern string_intern_t;

string_intern_t* string_intern_create(void);
void string_intern_destroy(string_intern_t* intern);
const char* string_intern(string_intern_t* intern, const char* str);
size_t string_intern_get_count(const string_intern_t* intern);

/* String utilities for kernel */
char* kstrdup(const char* str);
char* kstrndup(const char* str, size_t n);
char* kstrcpy(char* dest, const char* src);
char* kstrncpy(char* dest, const char* src, size_t n);
char* kstrcat(char* dest, const char* src);
char* kstrncat(char* dest, const char* src, size_t n);
int kstrcmp(const char* str1, const char* str2);
int kstrncmp(const char* str1, const char* str2, size_t n);
size_t kstrlen(const char* str);
size_t kstrnlen(const char* str, size_t maxlen);
char* kstrchr(const char* str, int c);
char* kstrrchr(const char* str, int c);
char* kstrstr(const char* haystack, const char* needle);
char* kstrtok(char* str, const char* delim);
char* kstrtok_r(char* str, const char* delim, char** saveptr);

/* String memory allocation */
char* str_alloc(size_t size);
char* str_alloc_copy(const char* str);
char* str_alloc_format(const char* format, ...);
void str_free(char* str);
void str_free_array(char** array, size_t count);

/* String constants */
#define STR_EMPTY ""
#define STR_NULL "(null)"
#define STR_NEWLINE "\n"
#define STR_TAB "\t"
#define STR_SPACE " "
#define STR_COMMA ","
#define STR_DOT "."
#define STR_SLASH "/"
#define STR_BACKSLASH "\\"
#define STR_COLON ":"
#define STR_SEMICOLON ";"
#define STR_QUOTE "\""
#define STR_SINGLE_QUOTE "'"
#define STR_EQUALS "="
#define STR_PLUS "+"
#define STR_MINUS "-"
#define STR_ASTERISK "*"
#define STR_QUESTION "?"
#define STR_EXCLAMATION "!"
#define STR_AT "@"
#define STR_HASH "#"
#define STR_DOLLAR "$"
#define STR_PERCENT "%"
#define STR_CARET "^"
#define STR_AMPERSAND "&"
#define STR_PIPE "|"
#define STR_TILDE "~"
#define STR_BACKTICK "`"

/* String limits */
#define STR_MAX_LENGTH 65536
#define STR_MAX_COUNT 10000
#define STR_DEFAULT_BUFFER_SIZE 1024
#define STR_MAX_FORMAT_LENGTH 4096

/* String validation macros */
#define STR_IS_EMPTY(str) ((str) == NULL || (str)[0] == '\0')
#define STR_IS_NOT_EMPTY(str) ((str) != NULL && (str)[0] != '\0')
#define STR_LENGTH(str) ((str) != NULL ? strlen(str) : 0)
#define STR_SAFE(str) ((str) != NULL ? (str) : STR_NULL)

/* String comparison macros */
#define STR_EQUALS(a, b) (strcmp((a), (b)) == 0)
#define STR_EQUALS_IGNORE_CASE(a, b) (strcasecmp((a), (b)) == 0)
#define STR_STARTS_WITH(str, prefix) (strncmp((str), (prefix), strlen(prefix)) == 0)
#define STR_ENDS_WITH(str, suffix) (strlen(str) >= strlen(suffix) && strcmp((str) + strlen(str) - strlen(suffix), (suffix)) == 0)

/* String allocation macros */
#define STR_ALLOC(size) malloc(size)
#define STR_ALLOC_COPY(str) strdup(str)
#define STR_ALLOC_FORMAT(format, ...) str_format(format, ##__VA_ARGS__)
#define STR_FREE(str) free(str)

/* Kernel string allocation macros */
#define KSTR_ALLOC(size) kmalloc(size)
#define KSTR_ALLOC_COPY(str) kstrdup(str)
#define KSTR_ALLOC_FORMAT(format, ...) kstr_format(format, ##__VA_ARGS__)
#define KSTR_FREE(str) kfree(str)

#endif /* STRING_H */