#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in user_target;
    memset(&user_target, 0, sizeof(user_target));
    user_target.sin_family = AF_INET;
    user_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    user_target.sin_port = htons((unsigned short)atoi(argv[1]));
    int result = connect(sock, (struct sockaddr *)&user_target, sizeof(user_target));
    close(sock);
    return result != 0;
}
