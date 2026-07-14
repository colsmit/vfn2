#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct sockaddr_in user_url;
    int descriptor;
    if (argc < 2) return 2;
    memset(&user_url, 0, sizeof(user_url));
    user_url.sin_family = AF_INET;
    user_url.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    user_url.sin_port = htons((unsigned short)atoi(argv[1]));
    descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) return 3;
    if (connect(descriptor, (struct sockaddr *)&user_url, sizeof(user_url)) != 0) return 4;
    puts("SSRF_EFFECT");
    close(descriptor);
    return 0;
}
