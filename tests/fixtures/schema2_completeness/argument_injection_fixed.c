#include <unistd.h>

extern char **environ;

int main(void) {
    char *fixed_arguments[] = {"/bin/echo", "SAFE_ARGUMENT", 0};
    execve("/bin/echo", fixed_arguments, environ);
    return 3;
}
