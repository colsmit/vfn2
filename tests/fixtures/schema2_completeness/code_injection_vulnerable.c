#include <stdio.h>
#include <string.h>

__attribute__((noinline)) int eval(const char *code) {
    if (strcmp(code, "CODE_EFFECT") == 0) {
        puts("CODE_EFFECT");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    return eval(argv[1]) ? 0 : 3;
}
