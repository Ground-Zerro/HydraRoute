#include "../include/bogon.h"
#include <sys/socket.h>

int bogon_check(const uint8_t *ip, int family) {
    if (family == AF_INET) {
        switch (ip[0]) {
        case 0:
        case 10:
        case 127:
            return 1;
        case 169:
            return ip[1] == 254;
        case 172:
            return (ip[1] & 0xF0) == 0x10;
        case 192:
            return ip[1] == 168;
        }
        if (ip[0] >= 224) return 1;
        return 0;
    }

    if (ip[0] == 0xFF) return 1;
    if ((ip[0] & 0xFE) == 0xFC) return 1;
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return 1;

    int all_zero = 1;
    for (int i = 0; i < 10; i++) {
        if (ip[i]) { all_zero = 0; break; }
    }
    if (all_zero) {
        if (ip[10] == 0xFF && ip[11] == 0xFF) return 1;
        if (ip[10] == 0 && ip[11] == 0) return 1;
    }
    return 0;
}
