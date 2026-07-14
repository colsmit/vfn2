#include <stdlib.h>

__attribute__((noinline)) static int authenticate(const char *username, const char *password) {
    return username && password && username[0] && password[0];
}

int main(void) {
    return !authenticate(getenv("APP_USER"), getenv("APP_PASSWORD"));
}
