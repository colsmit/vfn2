__attribute__((noinline)) static unsigned sha256(const unsigned char *data) {
    return (unsigned)data[0] * 65537U;
}

int main(void) {
    return (int)sha256((const unsigned char *)"security-data");
}
