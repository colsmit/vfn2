#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *token = getenv("SERVICE_API_TOKEN");
    if (token != NULL) {
        puts("token supplied at runtime");
    }
    return 0;
}
