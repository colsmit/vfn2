__attribute__((noinline)) static void ssl_ctx_set_verify(void *context, int verify_mode, void *callback) {
    (void)context; (void)verify_mode; (void)callback;
}

int main(void) {
    ssl_ctx_set_verify((void *)1, 0, (void *)0);
    return 0;
}
