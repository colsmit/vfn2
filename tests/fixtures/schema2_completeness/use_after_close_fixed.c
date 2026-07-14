#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0) return 2;
    char byte = 0;
    read(descriptor, &byte, 1);
    close(descriptor);
    puts("SCHEMA2_USE_AFTER_CLOSE");
    return 0;
}
