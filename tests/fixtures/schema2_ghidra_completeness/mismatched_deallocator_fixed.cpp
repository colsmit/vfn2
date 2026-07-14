#include <cstdio>

int main() {
    char *pointer = new char[16];
    std::puts("SCHEMA2_MISMATCHED_DEALLOCATOR");
    delete[] pointer;
    return 0;
}
