#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void safe_bounded_write(const char *input) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%s", input);
}

static int guarded_index(const unsigned char *data, size_t len, size_t index) {
    if (index >= len) {
        return 0;
    }
    return data[index];
}

static void truncating_api(const char *input) {
    char buf[8];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
}

static void unreachable_helper_sink(const char *input) {
    char buf[8];
    strcpy(buf, input);
}

static void native_only_crash_fixture(const char *input) {
    if (input && strcmp(input, "LOCAL_HARNESS_ONLY") == 0) {
        abort();
    }
}

static void unresolved_function_entry_sink(const char *input) {
    char buf[8];
    strcpy(buf, input);
}

static int benign_parser_input(const char *line) {
    unsigned int value = 0;
    if (sscanf(line, "%7u", &value) != 1) {
        return 0;
    }
    return value < 10;
}

void negative_precision_corpus_anchor(const char *input) {
    const unsigned char data[] = {1, 2, 3, 4};
    safe_bounded_write(input);
    (void)guarded_index(data, sizeof(data), 1);
    truncating_api(input);
    native_only_crash_fixture("safe");
    (void)benign_parser_input("7");
    (void)unreachable_helper_sink;
    (void)unresolved_function_entry_sink;
}
