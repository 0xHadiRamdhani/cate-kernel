#ifndef STDIO_H
#define STDIO_H

#include "stddef.h"
#include "stdarg.h"

/* Standard I/O functions for kernel */

/* File operations */
typedef struct {
    int fd;
    const char* path;
    size_t size;
    size_t position;
    bool readable;
    bool writable;
    bool seekable;
    void* private_data;
} FILE;

/* Standard file descriptors */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* Standard streams */
#define stdin ((FILE*)STDIN_FILENO)
#define stdout ((FILE*)STDOUT_FILENO)
#define stderr ((FILE*)STDERR_FILENO)

/* File operations */
FILE* fopen(const char* path, const char* mode);
FILE* fdopen(int fd, const char* mode);
FILE* freopen(const char* path, const char* mode, FILE* stream);
int fclose(FILE* stream);
int fcloseall(void);

/* File descriptor operations */
int open(const char* path, int flags, ...);
int close(int fd);
int creat(const char* path, mode_t mode);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int dup3(int oldfd, int newfd, int flags);

/* File I/O operations */
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);
ssize_t read(int fd, void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count);
ssize_t pread(int fd, void* buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset);

/* File positioning */
int fseek(FILE* stream, long offset, int whence);
long ftell(FILE* stream);
void rewind(FILE* stream);
int fgetpos(FILE* stream, fpos_t* pos);
int fsetpos(FILE* stream, const fpos_t* pos);
off_t lseek(int fd, off_t offset, int whence);

/* File status */
int feof(FILE* stream);
int ferror(FILE* stream);
void clearerr(FILE* stream);
int fileno(FILE* stream);

/* Formatted output */
int printf(const char* format, ...);
int fprintf(FILE* stream, const char* format, ...);
int sprintf(char* str, const char* format, ...);
int snprintf(char* str, size_t size, const char* format, ...);
int vprintf(const char* format, va_list ap);
int vfprintf(FILE* stream, const char* format, va_list ap);
int vsprintf(char* str, const char* format, va_list ap);
int vsnprintf(char* str, size_t size, const char* format, va_list ap);

/* Formatted input */
int scanf(const char* format, ...);
int fscanf(FILE* stream, const char* format, ...);
int sscanf(const char* str, const char* format, ...);
int vscanf(const char* format, va_list ap);
int vfscanf(FILE* stream, const char* format, va_list ap);
int vsscanf(const char* str, const char* format, va_list ap);

/* Character I/O */
int fgetc(FILE* stream);
int getc(FILE* stream);
int getchar(void);
int fputc(int c, FILE* stream);
int putc(int c, FILE* stream);
int putchar(int c);
int ungetc(int c, FILE* stream);

/* Line I/O */
char* fgets(char* str, int n, FILE* stream);
char* gets(char* str);
int fputs(const char* str, FILE* stream);
int puts(const char* str);

/* Binary I/O */
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);

/* File positioning constants */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* File open modes */
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0040
#define O_EXCL   0x0080
#define O_TRUNC  0x0200
#define O_APPEND 0x0400

/* File permissions */
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

/* Buffer sizes */
#define BUFSIZ 8192
#define FILENAME_MAX 4096
#define FOPEN_MAX 16
#define L_tmpnam 20
#define TMP_MAX 238328

/* File position type */
typedef long fpos_t;
typedef long off_t;
typedef unsigned int mode_t;

/* Error indicators */
#define EOF (-1)

/* Kernel-specific I/O functions */
FILE* kfopen(const char* path, const char* mode);
int kfclose(FILE* stream);
size_t kfread(void* ptr, size_t size, size_t nmemb, FILE* stream);
size_t kfwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);
int kprintf(const char* format, ...);
int kfprintf(FILE* stream, const char* format, ...);
int ksprintf(char* str, const char* format, ...);
int ksnprintf(char* str, size_t size, const char* format, ...);
int kvprintf(const char* format, va_list ap);
int kvfprintf(FILE* stream, const char* format, va_list ap);
int kvsprintf(char* str, const char* format, va_list ap);
int kvsnprintf(char* str, size_t size, const char* format, va_list ap);

/* Kernel console I/O */
int kgetchar(void);
int kputchar(int c);
char* kgets(char* str, int n);
int kputs(const char* str);

/* Kernel debug I/O */
int kdebug_printf(const char* format, ...);
int kdebug_vprintf(const char* format, va_list ap);

/* Kernel error I/O */
int kerror_printf(const char* format, ...);
int kerror_vprintf(const char* format, va_list ap);

/* Kernel log I/O */
int klog_printf(const char* format, ...);
int klog_vprintf(const char* format, va_list ap);

/* Formatted output helpers */
int print_hex(u64 value);
int print_dec(u64 value);
int print_bin(u64 value);
int print_oct(u64 value);
int print_ptr(const void* ptr);
int print_string(const char* str);

/* Formatted input helpers */
int scan_hex(u64* value);
int scan_dec(u64* value);
int scan_bin(u64* value);
int scan_oct(u64* value);
int scan_string(char* str, size_t size);

/* Buffer management */
typedef struct {
    char* data;
    size_t size;
    size_t pos;
    bool eof;
    bool error;
} buffer_t;

buffer_t* buffer_create(size_t size);
void buffer_destroy(buffer_t* buffer);
int buffer_printf(buffer_t* buffer, const char* format, ...);
int buffer_vprintf(buffer_t* buffer, const char* format, va_list ap);
size_t buffer_write(buffer_t* buffer, const void* data, size_t size);
size_t buffer_read(buffer_t* buffer, void* data, size_t size);

/* Circular buffer */
typedef struct {
    char* data;
    size_t size;
    size_t head;
    size_t tail;
    size_t count;
    bool full;
} circular_buffer_t;

circular_buffer_t* circular_buffer_create(size_t size);
void circular_buffer_destroy(circular_buffer_t* buffer);
bool circular_buffer_write(circular_buffer_t* buffer, char c);
bool circular_buffer_read(circular_buffer_t* buffer, char* c);
size_t circular_buffer_available(circular_buffer_t* buffer);
bool circular_buffer_full(circular_buffer_t* buffer);
bool circular_buffer_empty(circular_buffer_t* buffer);

/* String buffer */
typedef struct {
    char* data;
    size_t size;
    size_t pos;
    size_t capacity;
} string_buffer_t;

string_buffer_t* string_buffer_create(size_t initial_capacity);
void string_buffer_destroy(string_buffer_t* buffer);
int string_buffer_printf(string_buffer_t* buffer, const char* format, ...);
int string_buffer_vprintf(string_buffer_t* buffer, const char* format, va_list ap);
const char* string_buffer_get_string(string_buffer_t* buffer);
size_t string_buffer_get_length(string_buffer_t* buffer);
void string_buffer_clear(string_buffer_t* buffer);

/* File operations for kernel */
int kopen(const char* path, int flags);
int kclose(int fd);
ssize_t kread(int fd, void* buf, size_t count);
ssize_t kwrite(int fd, const void* buf, size_t count);
off_t klseek(int fd, off_t offset, int whence);

/* Console operations */
void console_init(void);
void console_cleanup(void);
int console_printf(const char* format, ...);
int console_vprintf(const char* format, va_list ap);
void console_clear(void);
void console_set_color(int fg, int bg);

/* Debug console */
void debug_console_init(void);
void debug_console_cleanup(void);
int debug_console_printf(const char* format, ...);
int debug_console_vprintf(const char* format, va_list ap);

/* Error console */
void error_console_init(void);
void error_console_cleanup(void);
int error_console_printf(const char* format, ...);
int error_console_vprintf(const char* format, va_list ap);

/* Log console */
void log_console_init(void);
void log_console_cleanup(void);
int log_console_printf(const char* format, ...);
int log_console_vprintf(const char* format, va_list ap);

/* I/O redirection */
void io_redirect_stdout(FILE* new_stdout);
void io_redirect_stderr(FILE* new_stderr);
void io_redirect_stdin(FILE* new_stdin);
void io_restore_stdout(void);
void io_restore_stderr(void);
void io_restore_stdin(void);

/* I/O buffering */
void io_set_buffering(FILE* stream, bool enabled);
bool io_get_buffering(FILE* stream);
void io_flush(FILE* stream);
void io_flush_all(void);

/* I/O error handling */
int io_get_error(FILE* stream);
void io_clear_error(FILE* stream);
bool io_has_error(FILE* stream);
bool io_has_eof(FILE* stream);

/* I/O statistics */
typedef struct {
    size_t bytes_read;
    size_t bytes_written;
    size_t operations_read;
    size_t operations_written;
    size_t errors_read;
    size_t errors_written;
} io_stats_t;

void io_get_stats(FILE* stream, io_stats_t* stats);
void io_reset_stats(FILE* stream);

/* I/O performance */
typedef struct {
    double read_speed;
    double write_speed;
    double avg_read_time;
    double avg_write_time;
    size_t peak_read_speed;
    size_t peak_write_speed;
} io_performance_t;

void io_get_performance(FILE* stream, io_performance_t* perf);
void io_reset_performance(FILE* stream);

#endif /* STDIO_H */