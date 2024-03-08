#pragma once

#include <stdbool.h>
#include <openssl/ssl.h>

#include "types.h"

enum state {
    UNAUTH, AUTH, CHECK_MAIL, LISTEN, FETCH
};

struct imap_session {
    BIO *web;
    SSL_CTX *ssl_ctx;
    const char *tag;
    int msgid;
    bool message_pending;
    void *msg_buf;
    int msg_buf_len;
    int msg_len;
    enum mode mode;
    enum state state;
};

int imap_create_session(void **session, enum mode mode, char *mode_arg);
int imap_wait_msg(void *session, void *out_msg, int out_len);
int imap_send_msg(void *session, void *send_msg, int send_len);
int imap_close_session(void *session);
