#include <stdlib.h>

__attribute__((noinline)) static int leaky_function(void) {
    char *resource = (char *)malloc(32);
    if (!resource) return 2;
    resource[0] = 'L';
    int result = resource[0] == 'L' ? 0 : 3;
    free(resource);
    return result;
}

int main(void) {
    return leaky_function();
}
