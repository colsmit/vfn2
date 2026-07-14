#include <stdio.h>

__attribute__((noinline)) static void redirect(const char *location) {
    printf("HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", location);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    redirect(argv[1]);
    return 0;
}
