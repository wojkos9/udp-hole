#pragma once

#include <netinet/in.h>
#include <stdint.h>

struct stun_addr {
    struct in_addr sin_addr;
    in_port_t sin_port;
    char tag;
};

int stun_get_external_addr(int udp_sock, struct stun_addr *out_addr);
