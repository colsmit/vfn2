#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static int eval(const char *code) {
    const char *proof = getenv("PROOF_FILE");
    if (strncmp(code, "WRITE:", 6) != 0 || !proof) return 0;
    FILE *stream = fopen(proof, "w");
    if (!stream) return -1;
    fprintf(stream, "{\"action\":\"write\",\"target\":\"proof\",\"value\":\"%s\"}\n", code + 6);
    fclose(stream);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    return eval(argv[1]) < 0;
}
