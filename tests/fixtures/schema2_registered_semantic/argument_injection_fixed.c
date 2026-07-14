#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    const char *proof = getenv("PROOF_FILE");
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) {
        FILE *stream = fopen(proof, "w");
        if (!stream) return 3;
        fprintf(stream, "{\"argv\":[\"--child\",\"%s\"]}\n", argv[2]);
        fclose(stream);
        return 0;
    }
    char *fixed_argv[] = {argv[0], "--child", "SAFE_FIXED_ARGUMENT", NULL};
    execve(argv[0], fixed_argv, environ);
    return 4;
}
