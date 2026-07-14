#include <stdio.h>

__attribute__((noinline)) static void set_header(const char *header) {
    printf("HTTP/1.1 200 OK\r\nX-Value: %s\r\n\r\n", header);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char safe[128];
    int out = 0;
    for (int in = 0; argv[1][in] && out < 127; ++in) {
        if (argv[1][in] != '\r' && argv[1][in] != '\n') safe[out++] = argv[1][in];
    }
    safe[out] = 0;
    set_header(safe);
    return 0;
}
