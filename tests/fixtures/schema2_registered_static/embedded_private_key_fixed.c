#include <stdlib.h>

__attribute__((noinline)) static int load_private_key(const char *key) {
    return key && key[0];
}

int main(void) {
    return !load_private_key(getenv("PRIVATE_KEY_PATH"));
}
