#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) static void log_message(const char *message) {
    FILE *stream = fopen(getenv("LOG_PATH"), "a");
    if (!stream) return;
    fprintf(stream, "EVENT:%s\n", message);
    fclose(stream);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    log_message(argv[1]);
    return 0;
}
