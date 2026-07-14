#include <stdio.h>
#include <string.h>

__attribute__((noinline)) int eval(const char *code) {
    if (strcmp(code, "return 1") == 0) {
        puts("SAFE_CODE");
        return 1;
    }
    return 0;
}

int main(void) {
    return eval("return 1") ? 0 : 3;
}
