#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    struct sockaddr_in fixed_address;
    int descriptor;
    memset(&fixed_address, 0, sizeof(fixed_address));
    fixed_address.sin_family = AF_INET;
    fixed_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fixed_address.sin_port = htons(9);
    descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) return 3;
    connect(descriptor, (struct sockaddr *)&fixed_address, sizeof(fixed_address));
    close(descriptor);
    return 0;
}
