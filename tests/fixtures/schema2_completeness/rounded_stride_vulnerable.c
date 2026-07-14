#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    size_t bits = 1;
    size_t samples = 3;
    size_t width = 9;
    size_t height = 3;
    size_t logical_row = (samples * bits * width + 7) / 8;
    size_t logical_size = logical_row * height;
    size_t stride = samples * ((bits * width + 7) / 8);
    size_t offset = (height - 1) * stride;
    uint8_t *source = calloc(logical_size + 16, 1);
    if (source == NULL) {
        return 2;
    }
    volatile uint8_t value = source[offset + 1];
    (void)value;
    if (offset + 1 >= logical_size) {
        puts("SCHEMA2_ROUNDED_STRIDE_OOB");
    }
    free(source);
    return 0;
}
