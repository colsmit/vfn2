#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) static int sql_exec(const char *query) {
    const char *database = getenv("DATABASE_PATH");
    const char *python = getenv("PYTHON_BIN");
    pid_t child = fork();
    if (child == 0) {
        execl(python, python, "-c", "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.executescript(sys.argv[2]);c.commit()", database, query, (char *)0);
        _exit(127);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return status;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    return sql_exec(argv[1]);
}
