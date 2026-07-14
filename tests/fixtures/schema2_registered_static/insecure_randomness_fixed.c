#include <sys/random.h>

__attribute__((noinline)) static int consume_nonce(int value) {
    return value == -1;
}

int main(void) {
    int nonce = 0;
    if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) return 2;
    return consume_nonce(nonce);
}
