#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <err.h>
#include <getopt.h>

#include "stun.h"
#include "imap.h"
#include "socket.h"

struct comm_socket {
    int udp_sock;
    struct stun_addr own_addr;
    struct stun_addr peer_addr;
};

int create_comm_socket(struct comm_socket *out_socket, int server_port) {
    int r;
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) return -1;

    out_socket->udp_sock = udp_sock;

    struct sockaddr_in sin = {
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(server_port),
        .sin_family = AF_INET
    };

    r = bind(udp_sock, (const struct sockaddr *)&sin, sizeof(sin));
    if (r) return -1;
    r = stun_get_external_addr(udp_sock, &out_socket->own_addr);

    fprintf(stderr, "Own addr: %s:%d\n", inet_ntoa(out_socket->own_addr.sin_addr),
        ntohs(out_socket->own_addr.sin_port)
    );

    if (r == -1) {
        return -1;
    }
    return 0;
}

struct addr_xchg_ops {
    int (*create_session)(void **session, enum mode mode, char *mode_arg);
    int (*wait_msg)(void *session, void *out_msg, int out_len);
    int (*send_msg)(void *session, void *send_msg, int send_len);
    int (*close_session)(void *session);
};

static const struct addr_xchg_ops imap_xchg_ops =  {
    .create_session = imap_create_session,
    .wait_msg = imap_wait_msg,
    .send_msg = imap_send_msg,
    .close_session = imap_close_session
};

static const struct addr_xchg_ops tcp_xchg_ops =  {
    .create_session = tcp_create_session,
    .wait_msg = tcp_wait_msg,
    .send_msg = tcp_send_msg,
    .close_session = tcp_close_session
};

int main(int argc, char *argv[]) {
    int r;
    struct comm_socket comm_socket;
    enum mode mode = EMPTY;
    char *peer = NULL;

    const struct addr_xchg_ops *xchg = &tcp_xchg_ops;

    char *mode_arg = NULL;
    int server_port = 0;

    char c;
    while ((c = getopt(argc, argv, ":c:s:i")) != (char)-1) {
        switch (c) {
            case 'c':
                mode = CLIENT;
                mode_arg = optarg;
                break;
            case 's':
                mode = SERVER;
                server_port = atoi(optarg);
                break;
            case 'i':
                xchg = &imap_xchg_ops;
                break;
            case ':':
                if (optopt == 'c') {
                    mode = CLIENT;
                } else if (optopt == 's') {
                    mode = SERVER;
                }
                break;
        }
    }

    if (mode == EMPTY) {
        errx(1, "No mode set");
    }

    void *session;
    r = xchg->create_session(&session, mode, mode_arg);
    if (r < 0) {
        errx(1, "create session");
    }

    if (mode == SERVER) {
        r = xchg->wait_msg(session, &comm_socket.peer_addr, sizeof(comm_socket.peer_addr));
        if (r < 0) {
            errx(1, "server get message");
        }

        r = create_comm_socket(&comm_socket, server_port);
        if (r < 0) err(1, "create socket");

        r = xchg->send_msg(session, &comm_socket.own_addr, sizeof(comm_socket.own_addr));
    } else {
        r = create_comm_socket(&comm_socket, 0);
        if (r < 0) err(1, "create socket");

        r = xchg->send_msg(session, &comm_socket.own_addr, sizeof(comm_socket.own_addr));
        r = xchg->wait_msg(session, &comm_socket.peer_addr, sizeof(comm_socket.peer_addr));
        if (r < 0) {
            errx(1, "client get message");
        }
    }
    xchg->close_session(session);

    printf("Connection: %s:%d",
        inet_ntoa(comm_socket.own_addr.sin_addr),
        ntohs(comm_socket.own_addr.sin_port)
    );

    printf(" <-> %s:%d\n",
        inet_ntoa(comm_socket.peer_addr.sin_addr),
        ntohs(comm_socket.peer_addr.sin_port)
    );

    struct sockaddr_in own_sin = {
        .sin_addr = comm_socket.own_addr.sin_addr,
        .sin_port = comm_socket.own_addr.sin_port,
        .sin_family = AF_INET
    };

    struct sockaddr_in peer_sin = {
        .sin_addr = comm_socket.peer_addr.sin_addr,
        .sin_port = comm_socket.peer_addr.sin_port,
        .sin_family = AF_INET
    };

    fprintf(stderr, "Connecting sockfd %d\n", comm_socket.udp_sock);

    r = connect(comm_socket.udp_sock, (struct sockaddr *)&peer_sin, sizeof(peer_sin));
    if (r < 0) err(1, "connect");

    fprintf(stderr, "connected\n");

    int msgid = 1;
    while(1) {
        char buf[64];
        fprintf(stderr, "Write %d <-> %d\n", ntohs(comm_socket.own_addr.sin_port), ntohs(comm_socket.peer_addr.sin_port));
        r = snprintf(buf, sizeof(buf), "%s msg %d\n", mode == SERVER ? "server" : "client", msgid);
        ++msgid;
        write(comm_socket.udp_sock, buf, r);
        r = recv(comm_socket.udp_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (r > 0) {
            write(1, buf, r);
        }
        sleep(1);
    }

    return r;
}