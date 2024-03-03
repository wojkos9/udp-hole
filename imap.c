#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <getopt.h>
#include <err.h>

#include "user_data.h"
#include "imap.h"
#include "b64.h"

#define TAG "a001"

enum result {
    OK, BAD
};

typedef void (*scanner)(char *, struct imap_session *);

#define UNSEEN_TAG "UNSEEN"
void scan_unseen(char *line, struct imap_session *data) {
    char *r = strstr(line, UNSEEN_TAG);
    if (r) {
        int id = atoi(r + sizeof(UNSEEN_TAG));
        if (id) {
            data->msgid = id;
        }
    }
}

#define RECENT_TAG "EXISTS"
void scan_recent(char *line, struct imap_session *data) {
    if (strstr(line, RECENT_TAG)) {
        data->message_pending = true;
    }
}

#define SUBJECT_TAG "Subject:"
void scan_subject(char *line, struct imap_session *data) {
    if (strncmp(line, SUBJECT_TAG, sizeof(SUBJECT_TAG) - 1) == 0) {
        line += sizeof(SUBJECT_TAG);
        if (data->mode == SERVER && *line == 'c' || data->mode == CLIENT && *line == 's') {
            strtok(line, ":\r\n");
            char *msg_enc = strtok(NULL, ":\r\n");
            printf("DATA: %s\n", msg_enc);
            data->msg_len = b64decode(msg_enc, strlen(msg_enc), data->msg_buf, data->msg_buf_len);
        } else {
            printf("ERR DATA START: %c\n", *line);
        }
    }
}

int imap_write_raw(struct imap_session *data, const char *raw_data, int n) {
    fprintf(stderr, "C: %s", raw_data);
    return BIO_write(data->web, raw_data, n);
}

int imap_write(struct imap_session *data, const char *msg) {
    char buf[256];
    data->tag = TAG;
    int n = sprintf(buf, "%s %s\r\n", data->tag, msg);
    return imap_write_raw(data, buf, n);
}

int IMAP_get_line(BIO *web, char *buf, int n) {
    int r;
    char *buf0 = buf;
    while(buf - buf0 < n) {
        r = BIO_read(web, buf, 1);
        if (r < 0) return r;
        if (*buf == '\n') break;
        buf++;
    }
    *(++buf) = 0;
    return buf - buf0;
}

enum result imap_read(struct imap_session *data, scanner scanner) {
    char line[256];
    int r;
    do {
        r = IMAP_get_line(data->web, line, sizeof(line));
        if (r > 0) {
            fprintf(stderr, "S: %s", line);
            if (scanner && data) {
                scanner(line, data);
            }
            if (!strncmp(line, data->tag, strlen(data->tag)) || *line == '+') {
                break;
            }
        }
    } while (r > 0 || BIO_should_retry(data->web));

    strtok(line, " ");
    if (!strncmp(strtok(NULL, " "), "OK", strlen("OK"))) {
        return OK;
    }
    errx(1, "Protocol error: %s\n", line);
    return BAD;
}

enum result imap_cmd(struct imap_session *data, const char *msg) {
    imap_write(data, msg);
    return imap_read(data, NULL);
}

int imap_create_session(struct imap_session *session) {
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    BIO *web = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(web, IMAP_SERVER);

    BIO_do_connect(web);
    BIO_do_handshake(web);

    session->web = web;
    session->ssl_ctx = ctx;
    session->tag = "*";
    session->msgid = 0;
    session->msg_buf = 0;
    session->state = UNAUTH;

    imap_read(session, NULL);
    imap_write(session, "login " IMAP_CREDS);
    if (imap_read(session, NULL) != OK)
        return 1;
    session->state = AUTH;
    return 0;
}

int imap_close_session(struct imap_session *session) {
    BIO_free_all(session->web);
    SSL_CTX_free(session->ssl_ctx);
    return 0;
}

int imap_wait_msg(struct imap_session *session, void *out_msg, int out_len) {
    session->msg_buf = out_msg;
    session->msg_buf_len = out_len;
    session->msg_len = 0;
    while (1) {
        switch (session->state) {
        case AUTH:
            imap_write(session, "select xd");
            if (imap_read(session, scan_unseen) != OK)
                goto error;
            session->state = session->msgid ? FETCH : LISTEN;
            break;
        case LISTEN:
            sleep(5);
            imap_write(session, "noop");
            if (imap_read(session, scan_recent) != OK)
                goto error;
            if (session->message_pending) {
                session->state = AUTH;
            }
            break;
        case FETCH: {
            char cmd[64];
            sprintf(cmd, "fetch %d (BODY.PEEK[HEADER.FIELDS (Subject)])",
                    session->msgid);
            imap_write(session, cmd);
            if (imap_read(session, scan_subject) != OK)
                goto error;
            if (session->msg_len == 0) {
                session->state = LISTEN;
                continue;
            }
            sprintf(cmd, "store %d +flags \\Deleted", session->msgid);
            if (imap_cmd(session, cmd) != OK)
                goto error;
            if (imap_cmd(session, "expunge") != OK)
                goto error;
            session->msgid = 0;
            goto success;
            break;
        }
        default:
            errx(1, "Invalid IMAP state");
        }
        sleep(1);
    }
    error:
    return -1;
    success:
    return 0;
}

int imap_send_msg(struct imap_session *session, void *send_msg, int send_len) {
    char msg[64];
    char cmd[64];
    char buf[64];
    int n = b64encode(send_msg, send_len, buf);
    sprintf(msg, "Subject: %c:%.*s\r\n\r\n", session->mode == SERVER ? 's' : 'c', n, buf);
    int mlen = strlen(msg);
    sprintf(cmd, "append xd {%d}", mlen - 2);
    if (imap_cmd(session, cmd) != OK)
        return 1;
    imap_write_raw(session, msg, mlen);
    if (imap_read(session, NULL) != OK)
        return 1;
    return 0;
}
