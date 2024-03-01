#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <err.h>
#include <getopt.h>

#include "stun.h"
#include "imap.h"

struct comm_socket {
    int udp_sock;
    uint16_t external_port;
};

int create_comm_socket(struct comm_socket *out_socket) {
    int r;
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in sin = {
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = 0,
        .sin_family = AF_INET
    };

    r = bind(udp_sock, (const struct sockaddr *)&sin, sizeof(sin));
    if (r) return -1;
    uint16_t port = stun_get_external_port(udp_sock);
    if (port == (uint16_t)-1) {
        return -1;
    }
    out_socket->udp_sock = udp_sock;
    out_socket->external_port = port;
    fprintf(stderr, "Got port %d\n", port);
    return 0;
}

int main(int argc, char *argv[]) {
    int r;
    struct comm_socket comm_socket;
    enum mode mode = EMPTY;
    char *peer = NULL;

    char c;
    while ((c = getopt(argc, argv, "csp:")) != (char)-1) {
        switch (c) {
            case 'c':
                mode = CLIENT;
                break;
            case 's':
                mode = SERVER;
                break;
            case 'p':
                peer = optarg;
                break;
        }
    }

    if (mode == EMPTY) {
        errx(1, "No mode set");
    }
    if (peer == NULL) {
        errx(1, "No peer");
    }
    struct sockaddr_in peer_sin = {};
    r = inet_aton(peer, &peer_sin.sin_addr);
    if (r == 0) {
        errx(1, "Invalid peer");
    }

    struct imap_session session;
    r = imap_create_session(&session);
    if (r < 0) {
        errx(1, "create imap session");
    }

    session.mode = mode;

    uint16_t peer_port = 0;
    if (mode == SERVER) {
        int msg = imap_wait_msg(&session);
        if (msg < 0) {
            errx(1, "imap server get message");
        }
        peer_port = msg;
        create_comm_socket(&comm_socket);
        r = imap_send_msg(&session, comm_socket.external_port);
    } else {
        create_comm_socket(&comm_socket);
        r = imap_send_msg(&session, comm_socket.external_port);
        int msg = imap_wait_msg(&session);
        if (msg < 0) {
            errx(1, "imap client get message");
        }
        peer_port = msg;
    }
    imap_close_session(&session);

    printf("Connection: %d <-> %d\n", comm_socket.external_port, peer_port);

    peer_sin.sin_port = htons(peer_port);
    peer_sin.sin_family = AF_INET;

    while(1) {
        char buf[64];
        printf("Write %d <-> %d\n", comm_socket.external_port, peer_port);
        sendto(comm_socket.udp_sock, "msg", 3, 0, (struct sockaddr *)&peer_sin, sizeof(peer_sin));
        r = recv(comm_socket.udp_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (r > 0) {
            write(1, buf, r);
        }
        sleep(1);
    }

    return r;
}