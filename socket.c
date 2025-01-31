#include <asm-generic/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <err.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "socket.h"
#include "types.h"
#include "log.h"


int tcp_create_session(void **_session, enum mode mode, char *mode_arg) {
    struct tcp_session *session = malloc(sizeof(struct tcp_session));
    *(struct tcp_session **)_session = session;
    session->mode = mode;

    int r;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (mode == SERVER) {
        struct sockaddr_in sin = {
            .sin_addr = INADDR_ANY,
            .sin_port = htons(8000),
            .sin_family = AF_INET
        };

        debug("Binding\n");

        r = bind(s, (struct sockaddr *)&sin, sizeof(sin));
        if (r < 0) {
            perror("bind");
            return -1;
        }
        int on = 1;
        r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (r < 0) {
            perror("setopt reuseaddr");
            return -1;
        }
    } else {
        struct sockaddr_in sin = {
            .sin_addr = htonl(INADDR_LOOPBACK),
            .sin_port = htons(8000),
            .sin_family = AF_INET
        };
        if (mode_arg == NULL) {
            debug("Error. No server to connect to\n");
            return -1;
        }
        inet_aton(mode_arg, &sin.sin_addr);

        debug("Connecting\n");

        r = connect(s, (struct sockaddr *)&sin, sizeof(sin));
        if (r < 0) {
            perror("connect");
            return -1;
        }

        debug("Connected\n");
    }
    session->sockfd = s;
    debug("Session created %d\n", session->sockfd);
    return 0;
}

int tcp_wait_msg(void *_session, void *out_msg, int out_len) {
    struct tcp_session *session = _session;
    int r;

    debug("Waiting...\n");

    if (session->mode == SERVER) {
        debug("Listening\n");

        r = listen(session->sockfd, 1);
        if (r < 0) {
            perror("listen");
            return -1;
        }

        r = accept(session->sockfd, 0, 0);
        if (r < 0) {
            perror("accept");
            return -1;
        }
        close(session->sockfd);
        session->sockfd = r;

        debug("Connection received\n");
    }

    r = read(session->sockfd, out_msg, out_len);
    if (r < 0) {
        perror("read");
        return -1;
    }

    debug("Read %d bytes\n", r);
    return 0;
}

int tcp_send_msg(void *_session, void *send_msg, int send_len) {
    struct tcp_session *session = _session;
    int r;
    r = write(session->sockfd, send_msg, send_len);
    if (r < 0) return -1;

    debug("Written %d bytes\n", r);
    return 0;
}

int tcp_close_session(void *_session) {
    struct tcp_session *session = _session;
    close(session->sockfd);
    free(session);
    return 0;
}