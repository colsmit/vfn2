__attribute__((noinline)) static unsigned md5(const unsigned char *data) {
    return (unsigned)data[0] * 33U;
}

int main(void) {
    return (int)md5((const unsigned char *)"security-data");
}
