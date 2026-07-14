int main(void) {
    volatile int value = 7;
    volatile int *pointer = &value;
    return *pointer == 7 ? 0 : 1;
}
