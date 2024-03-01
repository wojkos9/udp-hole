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
    int message;
    enum mode mode;
    enum state state;
};

int imap_create_session(struct imap_session *session);
int imap_wait_msg(struct imap_session *session);
int imap_send_msg(struct imap_session *session, int send_msg);
int imap_close_session(struct imap_session *session);