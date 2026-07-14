#include <stdint.h>
#include <string.h>
#include <unistd.h>

static int guarded_heartbeat_copy(const unsigned char *record, size_t record_len) {
    unsigned char reply[64];
    uint16_t payload_len;

    if (record_len < 3) {
        return 0;
    }
    payload_len = (uint16_t)(((uint16_t)record[1] << 8) | record[2]);
    if ((size_t)payload_len > record_len - 3) {
        return 0;
    }
    memcpy(reply, record + 3, payload_len);
    return reply[0];
}

int main(void) {
    unsigned char record[8] = {0};
    ssize_t received = read(0, record, sizeof(record));

    if (received <= 0) {
        return 1;
    }
    return guarded_heartbeat_copy(record, (size_t)received);
}
