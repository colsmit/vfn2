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
    char safe[128];
    int out = 0;
    for (int in = 0; argv[1][in] && out < 127; ++in) {
        safe[out++] = (argv[1][in] == '\r' || argv[1][in] == '\n') ? '_' : argv[1][in];
    }
    safe[out] = 0;
    log_message(safe);
    return 0;
}
