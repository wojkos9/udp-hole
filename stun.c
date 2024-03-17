#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>

#include "stun.h"

struct stun_hdr {
    uint16_t mtyp;
    uint16_t mlen;
    uint32_t cookie;
    uint32_t tid[3];
};

struct stun_attr {
    uint16_t type;
    uint16_t len;
    uint32_t value;
};

struct stun_xor_mapped_addr_attr {
    uint16_t type;
    uint16_t len;
    uint8_t res;
    uint8_t proto;
    uint16_t port_xor;
    uint32_t ip_xor;
};

struct stun_bind_req_msg {
    struct stun_hdr hdr;
    struct stun_attr attr;
};

struct stun_xor_addr_msg {
    struct stun_hdr hdr;
    struct stun_xor_mapped_addr_attr attr;
};

// const char *stun_host = "stun2.l.google.com";
// const in_port_t stun_port = 19302;
const char *stun_host = "stun.cloudflare.com";
const in_port_t stun_port = 3478;

int stun_get_external_addr(int udp_sock, struct stun_addr *out_addr) {
    int r;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0
    };

    struct addrinfo *res;
    r = getaddrinfo(stun_host, NULL, &hints, &res);
    if (r) {
        return -1;
    }

    struct stun_bind_req_msg msg = {
        .hdr = {
            .mtyp = htons(1),
            .mlen = htons(sizeof(struct stun_attr)),
            .cookie = htonl(0x2112a442)
        },
        .attr = {
            .type = htons(3),
            .len = htons(4),
            .value = 0
        }
    };

    int rng = open("/dev/random", O_RDONLY);
    read(rng, &msg.hdr.tid, sizeof(msg.hdr.tid));
    close(rng);

    struct sockaddr_in sin = {
        .sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr,
        .sin_port = htons(stun_port),
        .sin_family = AF_INET
    };
    r = sendto(udp_sock, &msg, sizeof(msg), 0, (const struct sockaddr *)&sin, sizeof(sin));
    if (r < 0) err(1, "send");
    puts("sent");

    struct stun_xor_addr_msg msg_resp;
    r = read(udp_sock, &msg_resp, sizeof(msg_resp));
    if (r < 0) err(1, "read");
    puts("read");

    if (ntohs(msg_resp.attr.type) != 0x0020) {
        return 0;
    }
    printf("%x\n", msg_resp.attr.ip_xor);

    out_addr->sin_port = msg_resp.attr.port_xor ^ htons(0x2112);
    out_addr->sin_addr.s_addr = msg_resp.attr.ip_xor ^ htonl(0x2112a442);
    return 0;
}
