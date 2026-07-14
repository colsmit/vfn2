#include <stdio.h>

__attribute__((noinline)) static void set_header(const char *header) {
    printf("HTTP/1.1 200 OK\r\nX-Value: %s\r\n\r\n", header);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    set_header(argv[1]);
    return 0;
}
