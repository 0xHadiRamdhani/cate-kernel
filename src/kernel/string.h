#ifndef STRING_H
#define STRING_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

/* String manipulation functions */
size_t strlen(const char* str);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
char* strcat(char* dest, const char* src);
char* strncat(char* dest, const char* src, size_t n);
int strcmp(const char* str1, const char* str2);
int strncmp(const char* str1, const char* str2, size_t n);
char* strchr(const char* str, int c);
char* strrchr(const char* str, int c);
char* strstr(const char* haystack, const char* needle);

/* Memory manipulation functions */
void* memset(void* dest, int value, size_t n);
void* memcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
int memcmp(const void* ptr1, const void* ptr2, size_t n);
void* memchr(const void* ptr, int value, size_t n);

/* Safe string functions */
size_t strlcpy(char* dest, const char* src, size_t size);
size_t strlcat(char* dest, const char* src, size_t size);

/* String conversion functions */
char* itoa(int value, char* str, int base);
char* utoa(unsigned int value, char* str, int base);
char* ltoa(long value, char* str, int base);
char* ultoa(unsigned long value, char* str, int base);
char* lltoa(long long value, char* str, int base);
char* ulltoa(unsigned long long value, char* str, int base);

int atoi(const char* str);
long atol(const char* str);
long long atoll(const char* str);
unsigned int strtou(const char* str, char** endptr, int base);
unsigned long strtoul(const char* str, char** endptr, int base);
unsigned long long strtoull(const char* str, char** endptr, int base);

/* String tokenization */
char* strtok(char* str, const char* delim);
char* strtok_r(char* str, const char* delim, char** saveptr);

/* String span functions */
size_t strspn(const char* str, const char* accept);
size_t strcspn(const char* str, const char* reject);
char* strpbrk(const char* str, const char* accept);

/* String duplication */
char* strdup(const char* str);

/* Case-insensitive string functions */
int strcasecmp(const char* str1, const char* str2);
int strncasecmp(const char* str1, const char* str2, size_t n);

/* Character classification */
int tolower(int c);
int toupper(int c);
int isalnum(int c);
int isalpha(int c);
int isdigit(int c);
int islower(int c);
int isupper(int c);
int isspace(int c);
int isprint(int c);
int iscntrl(int c);
int ispunct(int c);
int isxdigit(int c);

/* String case conversion */
char* strlwr(char* str);
char* strupr(char* str);

/* Safe string length */
size_t strnlen(const char* str, size_t maxlen);

/* Memory functions */
void* memccpy(void* dest, const void* src, int c, size_t n);
void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen);

/* Formatted output functions */
int snprintf(char* str, size_t size, const char* format, ...);
int vsnprintf(char* str, size_t size, const char* format, va_list args);

/* Memory allocation functions (need to be implemented elsewhere) */
void* kmalloc(size_t size);
void kfree(void* ptr);

#endif /* STRING_H */