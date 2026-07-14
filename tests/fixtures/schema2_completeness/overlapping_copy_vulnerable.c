#include <stdio.h>
#include <string.h>

int main(void) {
    char buffer[8] = "abcdef";
    memcpy(buffer + 1, buffer, 4);
    puts("SCHEMA2_OVERLAPPING_COPY");
    return buffer[0] == 'a' ? 0 : 1;
}
