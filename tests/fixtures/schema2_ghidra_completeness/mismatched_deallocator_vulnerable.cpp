#include <cstdio>
#include <cstdlib>

int main() {
    char *pointer = new char[16];
    std::puts("SCHEMA2_MISMATCHED_DEALLOCATOR");
    std::free(pointer);
    return 0;
}
