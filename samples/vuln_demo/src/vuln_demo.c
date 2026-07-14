#include <stdio.h>
#include <string.h>

/*
 * vulnerable_copy intentionally performs an unbounded copy into a fixed-size
 * stack buffer to provide a ground-truth overflow for the agent.
 */
void vulnerable_copy(const char *input) {
    char buf[16];
    strcpy(buf, input); /* UNSAFE: potential overflow */
    printf("vulnerable_copy: %s\n", buf);
}

/*
 * safe_copy provides nearby non-exploitable code so the agent can learn to
 * distinguish between risky and safe patterns.
 */
void safe_copy(const char *input) {
    char buf[16];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("safe_copy: %s\n", buf);
}

static void helper_echo(const char *label, const char *input) {
    printf("[%s] %s\n", label, input);
}

int main(int argc, char **argv) {
    const char *payload = (argc > 1) ? argv[1] : "hello";

    helper_echo("main", payload);
    vulnerable_copy(payload);
    safe_copy(payload);

    return 0;
}
