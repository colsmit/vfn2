#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

struct owner {
    unsigned char *data;
};

static unsigned char *relocating_copy(struct owner *owner, unsigned char *source) {
    unsigned char *previous = owner->data;
    unsigned char *replacement = malloc(32);
    if (replacement == NULL) {
        return NULL;
    }
    owner->data = replacement;
    if (source == previous) {
        puts("SCHEMA2_REENTRANT_COPY_UAF");
    }
    free(previous);
    return replacement;
}

static void select_arguments(struct owner *owner, bool alternate_mode, unsigned char **out) {
    unsigned char *source = owner->data;
    bool no_copy = alternate_mode;
    if ((no_copy) || (source == NULL)) {
        no_copy = false;
    }
    else {
        no_copy = true;
    }
    if (no_copy) {
        *out = source;
    }
    else {
        unsigned char *result = relocating_copy(owner, source);
        *out = result;
    }
}

int main(void) {
    struct owner owner = {malloc(32)};
    unsigned char *arguments = NULL;
    if (owner.data == NULL) {
        return 2;
    }
    select_arguments(&owner, true, &arguments);
    free(owner.data);
    return arguments == NULL;
}
