#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void vulnerable_copy(const char *payload)
{
    size_t capacity = 16;
    char *buf = malloc(capacity);
    if (!buf) {
        return;
    }
    /*
     * The QEMU proof oracle should observe writes beyond the allocation
     * redzone when payload is longer than capacity.  The program exits
     * normally so crashes are not used as the success condition.
     */
    snprintf(buf, 128, "%s", payload ? payload : "");
    puts("vulnerable_copy");
    free(buf);
}

static const char *form_value(const char *body)
{
    const char *prefix = "payload=";
    size_t prefix_len = strlen(prefix);
    if (!body) {
        return "";
    }
    if (strncmp(body, prefix, prefix_len) == 0) {
        return body + prefix_len;
    }
    return body;
}

int main(void)
{
    char body[512];
    size_t nread = fread(body, 1, sizeof(body) - 1, stdin);
    body[nread] = '\0';
    vulnerable_copy(form_value(body));
    return 0;
}
