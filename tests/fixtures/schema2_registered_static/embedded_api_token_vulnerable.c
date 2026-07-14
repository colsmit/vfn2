#include <stddef.h>

__attribute__((noinline)) static int set_api_token(const char *token) {
    return token != NULL && token[0];
}

int main(void) {
    return !set_api_token("AbCDef_1234567890-ghIJ");
}
