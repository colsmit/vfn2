int main(void) {
    volatile int *pointer = (volatile int *)0;
    return *pointer;
}
