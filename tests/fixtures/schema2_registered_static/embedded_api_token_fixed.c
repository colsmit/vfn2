#include <stdlib.h>

__attribute__((noinline)) static int set_api_token(const char *token) {
    return token && token[0];
}

int main(void) {
    return !set_api_token(getenv("API_TOKEN"));
}
