#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in fixed_target;
    memset(&fixed_target, 0, sizeof(fixed_target));
    fixed_target.sin_family = AF_INET;
    fixed_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fixed_target.sin_port = htons(9);
    int result = connect(sock, (struct sockaddr *)&fixed_target, sizeof(fixed_target));
    close(sock);
    return result == 0;
}
