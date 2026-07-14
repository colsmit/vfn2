#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0) return 2;
    char byte = 0;
    close(descriptor);
    read(descriptor, &byte, 1);
    puts("SCHEMA2_USE_AFTER_CLOSE");
    return 0;
}
