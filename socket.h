#pragma once
#include <netinet/in.h>

#include "types.h"

struct tcp_session {
    int sockfd;
    enum mode mode;
    in_addr_t server_addr;
};

int tcp_create_session(void **session, enum mode mode, char *mode_arg);
int tcp_wait_msg(void *session, void *out_msg, int out_len);
int tcp_send_msg(void *session, void *send_msg, int send_len);
int tcp_close_session(void *session);
