#include <string.h>

__attribute__((noinline)) static int authenticate(const char *username, const char *password) {
    return username[0] && password[0];
}

int main(void) {
    return !authenticate("admin", "Firmware#42");
}
