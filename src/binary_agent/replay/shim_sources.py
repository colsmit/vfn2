"""Embedded C sources compiled by replay backends at runtime."""

_QEMU_NVRAM_SHIM_SOURCE = r"""
extern char *getenv(const char *);

struct nvram_item {
    char key[128];
    char value[2048];
};

static struct nvram_item nvram_store[128];

static int c_streq(const char *left, const char *right)
{
    unsigned index = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return 0;
        }
        index++;
    }
    return left[index] == right[index];
}

static unsigned c_strlen(const char *value)
{
    unsigned length = 0;
    if (!value) {
        return 0;
    }
    while (value[length] != '\0') {
        length++;
    }
    return length;
}

static void c_copy(char *dst, const char *src, unsigned limit)
{
    unsigned index = 0;
    if (!dst || limit == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (index + 1 < limit && src[index] != '\0') {
        dst[index] = src[index];
        index++;
    }
    dst[index] = '\0';
}

static void make_env_name(const char *name, char *dst, unsigned limit)
{
    unsigned in = 0;
    unsigned out = 0;
    const char prefix[] = "NVRAM_";
    while (prefix[out] != '\0' && out + 1 < limit) {
        dst[out] = prefix[out];
        out++;
    }
    while (name && name[in] != '\0' && out + 1 < limit) {
        char ch = name[in++];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
            dst[out++] = ch;
        } else {
            dst[out++] = '_';
        }
    }
    if (limit != 0) {
        dst[out] = '\0';
    }
}

static const char *stored_value(const char *name)
{
    unsigned index = 0;
    while (index < 128) {
        if (nvram_store[index].key[0] != '\0' && c_streq(nvram_store[index].key, name)) {
            return nvram_store[index].value;
        }
        index++;
    }
    return 0;
}

char *nvram_get_safe(const char *name, char *buf, unsigned len)
{
    char env_name[192];
    const char *value = 0;
    make_env_name(name, env_name, sizeof(env_name));
    value = getenv(env_name);
    if (!value) {
        value = stored_value(name);
    }
    if (!value) {
        if (buf && len) {
            buf[0] = '\0';
        }
        return 0;
    }
    if (c_strlen(value) + 1 > len) {
        if (buf && len) {
            buf[0] = '\0';
        }
        return 0;
    }
    c_copy(buf, value, len);
    return buf;
}

char *nvram_get(const char *name)
{
    static char buf[2048];
    return nvram_get_safe(name, buf, sizeof(buf));
}

int nvram_set(const char *name, const char *value)
{
    unsigned index = 0;
    unsigned empty = 128;
    if (!name || !value) {
        return -1;
    }
    while (index < 128) {
        if (nvram_store[index].key[0] == '\0') {
            if (empty == 128) {
                empty = index;
            }
        } else if (c_streq(nvram_store[index].key, name)) {
            c_copy(nvram_store[index].value, value, sizeof(nvram_store[index].value));
            return 0;
        }
        index++;
    }
    if (empty == 128) {
        return -1;
    }
    c_copy(nvram_store[empty].key, name, sizeof(nvram_store[empty].key));
    c_copy(nvram_store[empty].value, value, sizeof(nvram_store[empty].value));
    return 0;
}

int nvram_unset(const char *name)
{
    unsigned index = 0;
    while (index < 128) {
        if (nvram_store[index].key[0] != '\0' && c_streq(nvram_store[index].key, name)) {
            nvram_store[index].key[0] = '\0';
            nvram_store[index].value[0] = '\0';
            return 0;
        }
        index++;
    }
    return 0;
}

int nvram_commit(void)
{
    return 0;
}
"""

_QEMU_REPLAYFS_SHIM_SOURCE = r"""
extern char *getenv(const char *);

#define REPLAYFS_MAX_ENTRIES 16
#define REPLAYFS_DIR_MAGIC 0x52465331u
#define DT_REG 8

typedef unsigned int size_t;

typedef struct replayfs_dir {
    unsigned magic;
    int next_index;
    char path[512];
} DIR;

struct dirent {
    unsigned long d_ino;
    long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

struct stat {
    unsigned char data[160];
};

static DIR replayfs_dirs[REPLAYFS_MAX_ENTRIES];

static int c_streq(const char *left, const char *right)
{
    unsigned index = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return 0;
        }
        index++;
    }
    return left[index] == right[index];
}

static unsigned c_strlen(const char *value)
{
    unsigned length = 0;
    if (!value) {
        return 0;
    }
    while (value[length] != '\0') {
        length++;
    }
    return length;
}

static void c_copy(char *dst, const char *src, unsigned limit)
{
    unsigned index = 0;
    if (!dst || limit == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (index + 1 < limit && src[index] != '\0') {
        dst[index] = src[index];
        index++;
    }
    dst[index] = '\0';
}

static void c_zero(void *ptr, unsigned length)
{
    unsigned index = 0;
    unsigned char *bytes = (unsigned char *)ptr;
    while (bytes && index < length) {
        bytes[index++] = 0;
    }
}

static int c_atoi(const char *value)
{
    int result = 0;
    unsigned index = 0;
    if (!value) {
        return 0;
    }
    while (value[index] >= '0' && value[index] <= '9') {
        result = result * 10 + (value[index] - '0');
        index++;
    }
    return result;
}

static void env_name(const char *prefix, int index, char *dst, unsigned limit)
{
    unsigned out = 0;
    unsigned in = 0;
    char digit = (char)('0' + index);
    while (prefix[in] != '\0' && out + 1 < limit) {
        dst[out++] = prefix[in++];
    }
    if (out + 1 < limit) {
        dst[out++] = digit;
    }
    dst[out] = '\0';
}

static int configured_count(void)
{
    int count = c_atoi(getenv("REPLAYFS_COUNT"));
    if (count < 0) {
        return 0;
    }
    if (count > REPLAYFS_MAX_ENTRIES) {
        return REPLAYFS_MAX_ENTRIES;
    }
    return count;
}

static const char *entry_value(const char *prefix, int index)
{
    char name[64];
    env_name(prefix, index, name, sizeof(name));
    return getenv(name);
}

static int path_matches_dir(const char *left, const char *right)
{
    unsigned left_len = c_strlen(left);
    unsigned right_len = c_strlen(right);
    if (c_streq(left, right)) {
        return 1;
    }
    if (left_len + 1 == right_len && right[right_len - 1] == '/') {
        char tmp[512];
        c_copy(tmp, right, sizeof(tmp));
        tmp[right_len - 1] = '\0';
        return c_streq(left, tmp);
    }
    if (right_len + 1 == left_len && left[left_len - 1] == '/') {
        char tmp[512];
        c_copy(tmp, left, sizeof(tmp));
        tmp[left_len - 1] = '\0';
        return c_streq(tmp, right);
    }
    return 0;
}

static int path_join_matches(const char *dir, const char *name, const char *path)
{
    char full[768];
    unsigned out = 0;
    unsigned in = 0;
    while (dir && dir[in] != '\0' && out + 1 < sizeof(full)) {
        full[out++] = dir[in++];
    }
    if (out > 0 && full[out - 1] != '/' && out + 1 < sizeof(full)) {
        full[out++] = '/';
    }
    in = 0;
    while (name && name[in] != '\0' && out + 1 < sizeof(full)) {
        full[out++] = name[in++];
    }
    full[out] = '\0';
    return c_streq(full, path);
}

DIR *opendir(const char *name)
{
    int index;
    int count = configured_count();
    for (index = 0; index < count; index++) {
        const char *dir = entry_value("REPLAYFS_DIR_", index);
        if (path_matches_dir(name, dir)) {
            replayfs_dirs[index].magic = REPLAYFS_DIR_MAGIC;
            replayfs_dirs[index].next_index = 0;
            c_copy(replayfs_dirs[index].path, dir, sizeof(replayfs_dirs[index].path));
            return &replayfs_dirs[index];
        }
    }
    return (DIR *)0;
}

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    int index;
    int count = configured_count();
    if (!dirp || dirp->magic != REPLAYFS_DIR_MAGIC || !entry || !result) {
        return -1;
    }
    for (index = dirp->next_index; index < count; index++) {
        const char *dir = entry_value("REPLAYFS_DIR_", index);
        const char *name = entry_value("REPLAYFS_NAME_", index);
        if (path_matches_dir(dirp->path, dir) && name && name[0] != '\0') {
            c_zero(entry, sizeof(*entry));
            entry->d_ino = (unsigned long)(index + 1);
            entry->d_off = index + 1;
            entry->d_reclen = sizeof(*entry);
            entry->d_type = DT_REG;
            c_copy(entry->d_name, name, sizeof(entry->d_name));
            dirp->next_index = index + 1;
            *result = entry;
            return 0;
        }
    }
    *result = (struct dirent *)0;
    return 0;
}

int closedir(DIR *dirp)
{
    if (dirp && dirp->magic == REPLAYFS_DIR_MAGIC) {
        dirp->magic = 0;
    }
    return 0;
}

int stat(const char *path, struct stat *buf)
{
    int index;
    int count = configured_count();
    for (index = 0; index < count; index++) {
        const char *dir = entry_value("REPLAYFS_DIR_", index);
        const char *name = entry_value("REPLAYFS_NAME_", index);
        if (dir && name && path_join_matches(dir, name, path)) {
            unsigned char *bytes = (unsigned char *)buf;
            int size = c_atoi(entry_value("REPLAYFS_SIZE_", index));
            if (!size) {
                size = 1;
            }
            c_zero(buf, sizeof(*buf));
            bytes[44] = (unsigned char)(size & 0xff);
            bytes[45] = (unsigned char)((size >> 8) & 0xff);
            bytes[46] = (unsigned char)((size >> 16) & 0xff);
            bytes[47] = (unsigned char)((size >> 24) & 0xff);
            bytes[64] = 1;
            return 0;
        }
    }
    return -1;
}
"""

_NATIVE_SYSLOG_INTERPOSER_SOURCE = r"""
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

static void replay_write_syslog(int priority, const char *fmt, va_list ap)
{
    const char *path = getenv("REPLAY_SYSLOG_PATH");
    char buffer[8192];
    FILE *file = 0;
    if (!fmt) {
        fmt = "";
    }
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    if (path && path[0]) {
        file = fopen(path, "a");
    }
    if (!file) {
        file = stderr;
    }
    fprintf(file, "priority=%d message=%s\n", priority, buffer);
    if (file != stderr) {
        fclose(file);
    }
}

void syslog(int priority, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    replay_write_syslog(priority, fmt, ap);
    va_end(ap);
}

void vsyslog(int priority, const char *fmt, va_list ap)
{
    va_list copy;
    va_copy(copy, ap);
    replay_write_syslog(priority, fmt, copy);
    va_end(copy);
}
"""

_QEMU_OVERFLOW_ORACLE_PRELOAD_SOURCE = r"""
#include <stdarg.h>
#include <stddef.h>

extern char *getenv(const char *);
extern int open(const char *, int, ...);
extern int write(int, const void *, unsigned);
extern int close(int);

#define ORACLE_HEAP_SIZE (4u * 1024u * 1024u)
#define ORACLE_MAX_ALLOCS 8192u
#define ORACLE_REDZONE_SIZE 256u
#define ORACLE_REDZONE_BYTE 0xa5u
#define O_WRONLY 01
#define O_CREAT 0100
#define O_TRUNC 01000

struct oracle_alloc {
    unsigned char *ptr;
    unsigned capacity;
    unsigned total;
    unsigned active;
};

static unsigned char oracle_heap[ORACLE_HEAP_SIZE] __attribute__((aligned(16)));
static unsigned oracle_heap_used;
static struct oracle_alloc oracle_allocs[ORACLE_MAX_ALLOCS];
static int oracle_reported;

static unsigned c_strlen(const char *value)
{
    unsigned length = 0;
    if (!value) {
        return 0;
    }
    while (value[length] != '\0') {
        length++;
    }
    return length;
}

static void c_memset(unsigned char *dst, unsigned char value, unsigned count)
{
    unsigned index = 0;
    while (index < count) {
        dst[index++] = value;
    }
}

static void *oracle_alloc(unsigned size)
{
    unsigned capacity = size ? size : 1u;
    unsigned total = (capacity + ORACLE_REDZONE_SIZE + 15u) & ~15u;
    unsigned index = 0;
    unsigned char *ptr = 0;
    if (total > ORACLE_HEAP_SIZE || oracle_heap_used + total > ORACLE_HEAP_SIZE) {
        return 0;
    }
    ptr = oracle_heap + oracle_heap_used;
    oracle_heap_used += total;
    c_memset(ptr, 0, total);
    c_memset(ptr + capacity, ORACLE_REDZONE_BYTE, ORACLE_REDZONE_SIZE);
    while (index < ORACLE_MAX_ALLOCS) {
        if (!oracle_allocs[index].active) {
            oracle_allocs[index].ptr = ptr;
            oracle_allocs[index].capacity = capacity;
            oracle_allocs[index].total = total;
            oracle_allocs[index].active = 1u;
            break;
        }
        index++;
    }
    return ptr;
}

void *_Znwj(unsigned size)
{
    return oracle_alloc(size);
}

void *_Znaj(unsigned size)
{
    return oracle_alloc(size);
}

void _ZdlPv(void *ptr)
{
    (void)ptr;
}

void _ZdaPv(void *ptr)
{
    (void)ptr;
}

static struct oracle_alloc *find_alloc(const void *ptr)
{
    unsigned index = 0;
    while (index < ORACLE_MAX_ALLOCS) {
        if (oracle_allocs[index].active && oracle_allocs[index].ptr == (const unsigned char *)ptr) {
            return &oracle_allocs[index];
        }
        index++;
    }
    return 0;
}

static void append_char(char *dst, unsigned limit, unsigned *out, char ch)
{
    if (*out + 1u < limit) {
        dst[*out] = ch;
    }
    *out += 1u;
}

static void append_text(char *dst, unsigned limit, unsigned *out, const char *text)
{
    unsigned index = 0;
    const char *value = text ? text : "(null)";
    while (value[index] != '\0') {
        append_char(dst, limit, out, value[index++]);
    }
}

static void append_uint(char *dst, unsigned limit, unsigned *out, unsigned value)
{
    char tmp[16];
    unsigned count = 0;
    if (value == 0) {
        append_char(dst, limit, out, '0');
        return;
    }
    while (value && count < sizeof(tmp)) {
        tmp[count++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    while (count) {
        append_char(dst, limit, out, tmp[--count]);
    }
}

static void append_int(char *dst, unsigned limit, unsigned *out, int value)
{
    unsigned magnitude = 0;
    if (value < 0) {
        append_char(dst, limit, out, '-');
        magnitude = (unsigned)(0u - (unsigned)value);
    } else {
        magnitude = (unsigned)value;
    }
    append_uint(dst, limit, out, magnitude);
}

static unsigned format_into(char *dst, unsigned limit, const char *fmt, va_list ap)
{
    unsigned out = 0;
    unsigned index = 0;
    if (!fmt) {
        fmt = "";
    }
    while (fmt[index] != '\0') {
        char ch = fmt[index++];
        if (ch != '%') {
            append_char(dst, limit, &out, ch);
            continue;
        }
        ch = fmt[index++];
        if (ch == '\0') {
            append_char(dst, limit, &out, '%');
            break;
        }
        if (ch == 'l') {
            ch = fmt[index++];
        }
        if (ch == 's') {
            append_text(dst, limit, &out, va_arg(ap, const char *));
        } else if (ch == 'd' || ch == 'i') {
            append_int(dst, limit, &out, va_arg(ap, int));
        } else if (ch == 'u') {
            append_uint(dst, limit, &out, va_arg(ap, unsigned));
        } else if (ch == '%') {
            append_char(dst, limit, &out, '%');
        } else {
            append_char(dst, limit, &out, '?');
        }
    }
    if (dst && limit) {
        if (out < limit) {
            dst[out] = '\0';
        } else {
            dst[limit - 1u] = '\0';
        }
    }
    return out;
}

static void append_json_text(char *dst, unsigned limit, unsigned *out, const char *text)
{
    unsigned index = 0;
    const char *value = text ? text : "";
    append_char(dst, limit, out, '"');
    while (value[index] != '\0') {
        char ch = value[index++];
        if (ch == '"' || ch == '\\') {
            append_char(dst, limit, out, '\\');
        }
        if ((unsigned char)ch < 0x20u) {
            append_char(dst, limit, out, ' ');
        } else {
            append_char(dst, limit, out, ch);
        }
    }
    append_char(dst, limit, out, '"');
}

static void append_json_uint(char *dst, unsigned limit, unsigned *out, unsigned value)
{
    append_uint(dst, limit, out, value);
}

static void append_json_hex(char *dst, unsigned limit, unsigned *out, unsigned value)
{
    static const char digits[] = "0123456789abcdef";
    int shift = 28;
    int seen = 0;
    append_json_text(dst, limit, out, "0x");
    *out -= 1u;
    while (shift >= 0) {
        unsigned nibble = (value >> (unsigned)shift) & 0xfu;
        if (nibble || seen || shift == 0) {
            append_char(dst, limit, out, digits[nibble]);
            seen = 1;
        }
        shift -= 4;
    }
    append_char(dst, limit, out, '"');
}

static void write_report(
    char *dst,
    unsigned bound,
    const char *fmt,
    unsigned formatted_length,
    struct oracle_alloc *alloc,
    unsigned redzone_modified,
    unsigned first_modified,
    unsigned last_modified
)
{
    char payload[2048];
    unsigned out = 0;
    const char *path = getenv("REPLAY_OVERFLOW_PROOF_PATH");
    int fd = -1;
    unsigned bytes_written = formatted_length + 1u;
    unsigned overflow_observed = 0;
    if (oracle_reported || !path || !alloc || !redzone_modified) {
        return;
    }
    oracle_reported = 1;
    if (bytes_written > bound) {
        bytes_written = bound;
    }
    if (bytes_written > alloc->capacity) {
        overflow_observed = bytes_written - alloc->capacity;
    }
    append_char(payload, sizeof(payload), &out, '{');
    append_text(payload, sizeof(payload), &out, "\"status\":\"out_of_bounds_write_observed\",");
    append_text(payload, sizeof(payload), &out, "\"bug_observed\":true,");
    append_text(payload, sizeof(payload), &out, "\"redzone_modified\":true,");
    append_text(payload, sizeof(payload), &out, "\"capacity_bytes\":");
    append_json_uint(payload, sizeof(payload), &out, alloc->capacity);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"snprintf_bound_bytes\":");
    append_json_uint(payload, sizeof(payload), &out, bound);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"formatted_length\":");
    append_json_uint(payload, sizeof(payload), &out, formatted_length);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"bytes_written_including_nul\":");
    append_json_uint(payload, sizeof(payload), &out, bytes_written);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"overflow_bytes_observed\":");
    append_json_uint(payload, sizeof(payload), &out, overflow_observed);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"first_modified_offset\":");
    append_json_uint(payload, sizeof(payload), &out, first_modified);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"last_modified_offset\":");
    append_json_uint(payload, sizeof(payload), &out, last_modified);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"allocation_pointer\":");
    append_json_hex(payload, sizeof(payload), &out, (unsigned)alloc->ptr);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"destination_pointer\":");
    append_json_hex(payload, sizeof(payload), &out, (unsigned)dst);
    append_char(payload, sizeof(payload), &out, ',');
    append_text(payload, sizeof(payload), &out, "\"format\":");
    append_json_text(payload, sizeof(payload), &out, fmt);
    append_char(payload, sizeof(payload), &out, '}');
    append_char(payload, sizeof(payload), &out, '\n');
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, payload, out);
        close(fd);
    }
}

int snprintf(char *dst, unsigned bound, const char *fmt, ...)
{
    va_list ap;
    unsigned formatted_length = 0;
    unsigned first_modified = 0xffffffffu;
    unsigned last_modified = 0;
    unsigned redzone_modified = 0;
    struct oracle_alloc *alloc = find_alloc(dst);
    unsigned index = 0;
    va_start(ap, fmt);
    formatted_length = format_into(dst, bound, fmt, ap);
    va_end(ap);
    if (alloc) {
        while (index < ORACLE_REDZONE_SIZE) {
            if (alloc->ptr[alloc->capacity + index] != ORACLE_REDZONE_BYTE) {
                redzone_modified = 1u;
                if (first_modified == 0xffffffffu) {
                    first_modified = alloc->capacity + index;
                }
                last_modified = alloc->capacity + index;
            }
            index++;
        }
        write_report(dst, bound, fmt, formatted_length, alloc, redzone_modified, first_modified, last_modified);
    }
    return (int)formatted_length;
}
"""

_QEMU_MEMORY_WRITE_PLUGIN_SOURCE = r"""
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t alloc_call;
static uint64_t alloc_ret;
static uint64_t sink_call;
static uint64_t sink_ret;
static uint64_t capacity_fallback;
static uint64_t bound_fallback;
static const char *out_path;
static const char *oracle_kind;
static const char *destination_kind;

static struct qemu_plugin_register *reg_r0;
static struct qemu_plugin_register *reg_r1;
static struct qemu_plugin_register *reg_r4;
static GByteArray *reg_buf;

static uint64_t capacity_bytes;
static uint64_t allocation_pointer;
static uint64_t sink_pointer;
static uint64_t sink_bound;
static bool sink_active;
static bool oob_observed;
static bool uses_stack_destination;
static uint64_t first_oob;
static uint64_t last_oob;
static uint64_t store_count;
static bool report_written;

enum event_kind {
    EVENT_ALLOC_CALL = 1,
    EVENT_ALLOC_RET = 2,
    EVENT_SINK_CALL = 3,
    EVENT_SINK_RET = 4,
};

static uint64_t parse_u64(const char *value)
{
    if (!value || !*value) {
        return 0;
    }
    return g_ascii_strtoull(value, NULL, 0);
}

static uint64_t read_register_u64(struct qemu_plugin_register *handle)
{
    uint64_t value = 0;
    guint index = 0;
    if (!handle || !reg_buf) {
        return 0;
    }
    g_byte_array_set_size(reg_buf, 0);
    if (!qemu_plugin_read_register(handle, reg_buf)) {
        return 0;
    }
    while (index < reg_buf->len && index < sizeof(value)) {
        value |= ((uint64_t)reg_buf->data[index]) << (index * 8u);
        index++;
    }
    return value;
}

static bool register_alias(const char *name, const char *primary, const char *padded, const char *abi)
{
    return g_ascii_strcasecmp(name, primary) == 0
        || g_ascii_strcasecmp(name, padded) == 0
        || g_ascii_strcasecmp(name, abi) == 0;
}

static void write_report(void)
{
    FILE *fp;
    uint64_t overflow_bytes = 0;
    if (report_written || !out_path) {
        return;
    }
    report_written = true;
    if (oob_observed && last_oob >= first_oob) {
        overflow_bytes = last_oob - first_oob + 1u;
    }
    fp = fopen(out_path, "w");
    if (!fp) {
        return;
    }
    fprintf(
        fp,
        "{"
        "\"status\":\"%s\","
        "\"bug_observed\":%s,"
        "\"redzone_modified\":%s,"
        "\"kind\":\"%s\","
        "\"destination_kind\":\"%s\","
        "\"capacity_bytes\":%" PRIu64 ","
        "\"snprintf_bound_bytes\":%" PRIu64 ","
        "\"overflow_bytes_observed\":%" PRIu64 ","
        "\"first_oob_address\":\"0x%" PRIx64 "\","
        "\"last_oob_address\":\"0x%" PRIx64 "\","
        "\"allocation_pointer\":\"0x%" PRIx64 "\","
        "\"destination_pointer\":\"0x%" PRIx64 "\","
        "\"same_object\":%s,"
        "\"store_count\":%" PRIu64
        "}\n",
        oob_observed ? "out_of_bounds_write_observed" : "no_out_of_bounds_write_observed",
        oob_observed ? "true" : "false",
        oob_observed ? "true" : "false",
        oracle_kind ? oracle_kind : "bounded_write_overflow",
        destination_kind ? destination_kind : "",
        capacity_bytes,
        sink_bound,
        overflow_bytes,
        oob_observed ? first_oob : 0,
        oob_observed ? last_oob : 0,
        allocation_pointer,
        sink_pointer,
        allocation_pointer && sink_pointer && allocation_pointer == sink_pointer ? "true" : "false",
        store_count
    );
    fclose(fp);
}

static void event_cb(unsigned int vcpu_index, void *userdata)
{
    uintptr_t event = (uintptr_t)userdata;
    (void)vcpu_index;
    if (event == EVENT_ALLOC_CALL) {
        capacity_bytes = read_register_u64(reg_r0);
        if (!capacity_bytes) {
            capacity_bytes = capacity_fallback;
        }
    } else if (event == EVENT_ALLOC_RET) {
        allocation_pointer = read_register_u64(reg_r0);
    } else if (event == EVENT_SINK_CALL) {
        sink_pointer = read_register_u64(reg_r0);
        if (!sink_pointer) {
            sink_pointer = read_register_u64(reg_r4);
        }
        if (!capacity_bytes) {
            capacity_bytes = capacity_fallback;
        }
        sink_bound = read_register_u64(reg_r1);
        if (!sink_bound) {
            sink_bound = bound_fallback;
        }
        if (uses_stack_destination || !allocation_pointer) {
            allocation_pointer = sink_pointer;
        }
        sink_active = sink_pointer && allocation_pointer && capacity_bytes && sink_bound > capacity_bytes;
    } else if (event == EVENT_SINK_RET) {
        sink_active = false;
        write_report();
    }
}

static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr, void *userdata)
{
    uint64_t size;
    uint64_t start;
    uint64_t end;
    uint64_t oob_start;
    uint64_t oob_end;
    uint64_t overlap_start;
    uint64_t overlap_end;
    (void)vcpu_index;
    (void)userdata;
    if (!sink_active || !qemu_plugin_mem_is_store(info)) {
        return;
    }
    size = 1ull << qemu_plugin_mem_size_shift(info);
    start = vaddr;
    end = vaddr + size;
    oob_start = allocation_pointer + capacity_bytes;
    oob_end = allocation_pointer + sink_bound;
    if (end <= oob_start || start >= oob_end) {
        return;
    }
    overlap_start = start > oob_start ? start : oob_start;
    overlap_end = end < oob_end ? end : oob_end;
    if (overlap_start >= overlap_end) {
        return;
    }
    if (!oob_observed || overlap_start < first_oob) {
        first_oob = overlap_start;
    }
    if (!oob_observed || overlap_end - 1u > last_oob) {
        last_oob = overlap_end - 1u;
    }
    oob_observed = true;
    store_count++;
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t index;
    size_t count = qemu_plugin_tb_n_insns(tb);
    (void)id;
    for (index = 0; index < count; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        if (alloc_call && vaddr == alloc_call) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, event_cb, QEMU_PLUGIN_CB_R_REGS, (void *)(uintptr_t)EVENT_ALLOC_CALL);
        } else if (alloc_ret && vaddr == alloc_ret) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, event_cb, QEMU_PLUGIN_CB_R_REGS, (void *)(uintptr_t)EVENT_ALLOC_RET);
        } else if (vaddr == sink_call) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, event_cb, QEMU_PLUGIN_CB_R_REGS, (void *)(uintptr_t)EVENT_SINK_CALL);
        } else if (vaddr == sink_ret) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, event_cb, QEMU_PLUGIN_CB_R_REGS, (void *)(uintptr_t)EVENT_SINK_RET);
        }
        qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_W, NULL);
    }
}

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    GArray *registers;
    guint index;
    (void)id;
    (void)vcpu_index;
    registers = qemu_plugin_get_registers();
    for (index = 0; index < registers->len; index++) {
        qemu_plugin_reg_descriptor desc = g_array_index(registers, qemu_plugin_reg_descriptor, index);
        if (desc.name && register_alias(desc.name, "r0", "r00", "a1")) {
            reg_r0 = desc.handle;
        } else if (desc.name && register_alias(desc.name, "r1", "r01", "a2")) {
            reg_r1 = desc.handle;
        } else if (desc.name && register_alias(desc.name, "r4", "r04", "v1")) {
            reg_r4 = desc.handle;
        }
    }
    g_array_free(registers, TRUE);
    if (!reg_buf) {
        reg_buf = g_byte_array_sized_new(16);
    }
}

static void atexit_cb(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    write_report();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    int index;
    (void)info;
    for (index = 0; index < argc; index++) {
        if (g_str_has_prefix(argv[index], "out=")) {
            out_path = argv[index] + 4;
        } else if (g_str_has_prefix(argv[index], "kind=")) {
            oracle_kind = argv[index] + 5;
        } else if (g_str_has_prefix(argv[index], "destination_kind=")) {
            destination_kind = argv[index] + 17;
        } else if (g_str_has_prefix(argv[index], "alloc_call=")) {
            alloc_call = parse_u64(argv[index] + 11);
        } else if (g_str_has_prefix(argv[index], "alloc_ret=")) {
            alloc_ret = parse_u64(argv[index] + 10);
        } else if (g_str_has_prefix(argv[index], "sink_call=")) {
            sink_call = parse_u64(argv[index] + 10);
        } else if (g_str_has_prefix(argv[index], "sink_ret=")) {
            sink_ret = parse_u64(argv[index] + 9);
        } else if (g_str_has_prefix(argv[index], "capacity=")) {
            capacity_fallback = parse_u64(argv[index] + 9);
        } else if (g_str_has_prefix(argv[index], "bound=")) {
            bound_fallback = parse_u64(argv[index] + 6);
        }
    }
    uses_stack_destination = (destination_kind && g_ascii_strcasecmp(destination_kind, "stack") == 0)
        || (oracle_kind && strstr(oracle_kind, "stack") != NULL);
    if (!out_path || !sink_call || !sink_ret) {
        return 1;
    }
    if (!uses_stack_destination && (!alloc_call || !alloc_ret)) {
        return 1;
    }
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, atexit_cb, NULL);
    return 0;
}
"""

_QEMU_EXACT_ACCESS_PLUGIN_SOURCE = r"""
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t target_address;
static const char *out_path;
static bool observed;

static void write_report(uint64_t instruction, uint64_t address, unsigned size, bool is_store)
{
    FILE *fp;
    if (observed || !out_path) return;
    observed = true;
    fp = fopen(out_path, "w");
    if (!fp) return;
    fprintf(fp,
        "{\"schema_version\":1,\"status\":\"observed\","
        "\"kind\":\"exact_memory_access\",\"bug_observed\":false,"
        "\"instruction_address\":\"0x%" PRIx64 "\","
        "\"effective_address\":\"0x%" PRIx64 "\","
        "\"access_size_bytes\":%u,\"access_kind\":\"%s\"}\n",
        instruction, address, size, is_store ? "write" : "read");
    fclose(fp);
}

static void memory_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata)
{
    uint64_t instruction = (uint64_t)(uintptr_t)udata;
    unsigned size = 1u << qemu_plugin_mem_size_shift(info);
    (void)vcpu_index;
    write_report(instruction, vaddr, size, qemu_plugin_mem_is_store(info));
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t index;
    (void)id;
    for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        uint64_t address = qemu_plugin_insn_vaddr(insn);
        if (address == target_address) {
            qemu_plugin_register_vcpu_mem_cb(
                insn,
                memory_cb,
                QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW,
                (void *)(uintptr_t)address);
        }
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    int index;
    (void)info;
    for (index = 0; index < argc; index++) {
        if (g_str_has_prefix(argv[index], "target=")) target_address = g_ascii_strtoull(argv[index] + 7, NULL, 0);
        if (g_str_has_prefix(argv[index], "out=")) out_path = argv[index] + 4;
    }
    if (!target_address || !out_path) return 1;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    return 0;
}
"""

_QEMU_EXACT_INSTRUCTION_PLUGIN_SOURCE = r"""
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_TARGETS 256
static uint64_t targets[MAX_TARGETS];
static size_t target_count;
static uint64_t image_base;
static uint64_t runtime_base;
static const char *binary_name;
static const char *out_path;
static FILE *out_file;
static uint64_t hit_sequence;

struct instruction_match {
    uint64_t operation_address;
    uint64_t runtime_address;
};

static void discover_runtime_base(void)
{
    char line[4096];
    FILE *maps;
    if (runtime_base || !binary_name) return;
    maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start = 0;
        unsigned long long offset = 1;
        char path[3072] = {0};
        char *base;
        if (sscanf(line, "%llx-%*llx %*s %llx %*s %*s %3071s", &start, &offset, path) != 3) {
            continue;
        }
        base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (offset == 0 && !strcmp(base, binary_name)) {
            runtime_base = (uint64_t)start;
            break;
        }
    }
    fclose(maps);
}

static void instruction_cb(unsigned int vcpu_index, void *udata)
{
    struct instruction_match *match = (struct instruction_match *)udata;
    (void)vcpu_index;
    if (!out_file) return;
    hit_sequence++;
    fprintf(out_file,
        "{\"schema_version\":1,\"status\":\"observed\","
        "\"kind\":\"exact_instruction_execution\","
        "\"operation_address\":\"0x%" PRIx64 "\","
        "\"runtime_address\":\"0x%" PRIx64 "\","
        "\"hit_sequence\":%" PRIu64 ",\"bug_observed\":false}\n",
        match->operation_address, match->runtime_address, hit_sequence);
    fflush(out_file);
}

static uint64_t matched_target(uint64_t address)
{
    size_t index;
    discover_runtime_base();
    for (index = 0; index < target_count; index++) {
        uint64_t relative = targets[index] >= image_base ? targets[index] - image_base : targets[index];
        if (targets[index] == address ||
            (runtime_base && address == runtime_base + relative)) {
            return targets[index];
        }
    }
    return 0;
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t index;
    (void)id;
    for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        uint64_t address = qemu_plugin_insn_vaddr(insn);
        uint64_t target = matched_target(address);
        if (target) {
            struct instruction_match *match = g_new(struct instruction_match, 1);
            match->operation_address = target;
            match->runtime_address = address;
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, instruction_cb, QEMU_PLUGIN_CB_NO_REGS,
                match);
        }
    }
}

static void atexit_cb(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    if (out_file) {
        fflush(out_file);
        fclose(out_file);
        out_file = NULL;
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    int index;
    (void)info;
    for (index = 0; index < argc; index++) {
        if (g_str_has_prefix(argv[index], "out=")) out_path = argv[index] + 4;
        if (g_str_has_prefix(argv[index], "image_base=")) {
            image_base = g_ascii_strtoull(argv[index] + 11, NULL, 0);
        }
        if (g_str_has_prefix(argv[index], "binary_name=")) {
            binary_name = argv[index] + 12;
        }
        if (g_str_has_prefix(argv[index], "targets=")) {
            char **parts = g_strsplit(argv[index] + 8, ";", MAX_TARGETS + 1);
            size_t part;
            for (part = 0; parts[part] && target_count < MAX_TARGETS; part++) {
                char *end = NULL;
                uint64_t value = g_ascii_strtoull(parts[part], &end, 0);
                if (value && end && *end == '\0') targets[target_count++] = value;
            }
            g_strfreev(parts);
        }
    }
    if (!out_path || !target_count) return 1;
    out_file = fopen(out_path, "a");
    if (!out_file) return 1;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, atexit_cb, NULL);
    return 0;
}
"""

__all__ = (
    "_QEMU_NVRAM_SHIM_SOURCE",
    "_QEMU_REPLAYFS_SHIM_SOURCE",
    "_NATIVE_SYSLOG_INTERPOSER_SOURCE",
    "_QEMU_OVERFLOW_ORACLE_PRELOAD_SOURCE",
    "_QEMU_MEMORY_WRITE_PLUGIN_SOURCE",
    "_QEMU_EXACT_ACCESS_PLUGIN_SOURCE",
    "_QEMU_EXACT_INSTRUCTION_PLUGIN_SOURCE",
)
