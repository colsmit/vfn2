#include <stdlib.h>

__attribute__((noinline)) static int consume_nonce(int value) {
    return value == -1;
}

int main(void) {
    int nonce = rand();
    return consume_nonce(nonce);
}
