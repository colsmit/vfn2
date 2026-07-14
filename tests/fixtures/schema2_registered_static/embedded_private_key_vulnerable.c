#include <stddef.h>

__attribute__((noinline)) static int load_private_key(const char *key) {
    return key != NULL && key[0] == '-';
}

int main(void) {
    return !load_private_key("-----BEGIN PRIVATE KEY-----\nMDECAQMEBQYHCAkKCwwNDg8Q\n-----END PRIVATE KEY-----");
}
