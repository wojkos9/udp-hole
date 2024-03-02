#pragma once

#include <stdbool.h>
#include <openssl/ssl.h>

enum state {
    UNAUTH, AUTH, CHECK_MAIL, LISTEN, FETCH
};

enum mode {
    EMPTY, CLIENT, SERVER
};

struct imap_session {
    BIO *web;
    SSL_CTX *ssl_ctx;
    const char *tag;
    int msgid;
    bool message_pending;
    void *msg_buf;
    int msg_len;
    enum mode mode;
    enum state state;
};

int imap_create_session(struct imap_session *session);
int imap_wait_msg(struct imap_session *session, void *out_msg, int out_len);
int imap_send_msg(struct imap_session *session, void *send_msg, int send_len);
int imap_close_session(struct imap_session *session);