#include "stdint.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>

static const char b64_t[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

static const uint8_t b64_rt[] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
     0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
     0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0
};

int b64encode(void *data, int size, void *out) {
    int n = 0;
    for (uint8_t *a = data, *b = data, *end = data + size; a < end; a += (n % 4 != 0), b += (n % 4 != 2), n++) {
        int z = n % 4 << 1;
        *(char *)out++ = b64_t[(z == 0 ? 0 : (*a & ((1 << z) - 1)) << (6 - z)) | (z == 6 || b == end ? 0 : (*b & ~((1 << (z + 2)) - 1)) >> (z + 2))];
    }
    return n;
}

int b64decode(void *data, int size, void *out) {
    int n = 0;
    for (uint8_t *a = data, *end = data + size; a < end; a += 1 + (n % 3 == 2), n++) {
        int z = (n % 3) << 1;
        *(char*)out++ = (b64_rt[*a] & ((1 << (6 - z)) - 1)) << (z + 2) | (a == end - 1 ? 0 : b64_rt[*(a+1)] & ~((1 << (4 - z)) - 1)) >> (4 - z);
    }
    return n;
}

// int main() {
//     int n;
//     char buf[64];
//     struct sockaddr_in buf2;
//     struct sockaddr_in sin = {
//         .sin_port = htons(11075),
//         .sin_family = AF_INET
//     };
//     inet_aton("46.227.241.96", &sin.sin_addr);
//     n = b64encode(&sin, sizeof(sin), &buf);
//     write(1, buf, n);
//     write(1, "\n", 1);
//     n = b64decode(buf, n, &buf2);
//     printf("%s:%d\n", inet_ntoa(buf2.sin_addr), ntohs(buf2.sin_port));
//     return 0;
// }