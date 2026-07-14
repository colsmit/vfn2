#include <stdio.h>
#include <stdlib.h>

#define operator_new malloc
#define operator_delete free

int main(void) {
    void *pointer = operator_new(16);
    if (pointer == NULL) return 2;
    puts("SCHEMA2_MISMATCHED_DEALLOCATOR");
    operator_delete(pointer);
    return 0;
}
