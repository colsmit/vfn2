#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0) return 2;
    puts("SCHEMA2_DOUBLE_CLOSE");
    close(descriptor);
    return 0;
}
