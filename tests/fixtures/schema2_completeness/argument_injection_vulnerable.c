#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    char *user_argv[3];
    if (argc < 2) return 2;
    user_argv[0] = "/bin/echo";
    user_argv[1] = argv[1];
    user_argv[2] = 0;
    execve("/bin/echo", user_argv, environ);
    return 3;
}
