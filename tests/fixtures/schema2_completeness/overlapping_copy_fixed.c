#include <stdio.h>
#include <string.h>

int main(void) {
    char source[8] = "abcdef";
    char destination[8] = {0};
    memcpy(destination, source, 4);
    puts("SCHEMA2_OVERLAPPING_COPY");
    return destination[0] == 'a' ? 0 : 1;
}
