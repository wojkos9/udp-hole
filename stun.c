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
    uint16_t ip_xor;
};

struct stun_bind_req_msg {
    struct stun_hdr hdr;
    struct stun_attr attr;
};

struct stun_xor_addr_msg {
    struct stun_hdr hdr;
    struct stun_xor_mapped_addr_attr attr;
};

int main() {
    int r;
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in sin = {
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = 0,
        .sin_family = AF_INET
    };

    r = bind(s, (const struct sockaddr *)&sin, sizeof(sin));

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0
    };

    struct addrinfo *res;
    r = getaddrinfo("stun.cloudflare.com", NULL, &hints, &res);
    if (r) {
        errx(1, "getaddinfo");
    }

    sin.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    sin.sin_port = htons(3478);

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

    sendto(s, &msg, sizeof(msg), 0, (const struct sockaddr *)&sin, sizeof(sin));

    struct stun_xor_addr_msg msg_resp;
    read(s, &msg_resp, sizeof(msg_resp));

    if (ntohs(msg_resp.attr.type) != 0x0020) {
        return -1;
    }
    uint16_t port = ntohs(msg_resp.attr.port_xor) ^ 0x2112;
    printf("Port: %d\n", port);
    return 0;
}