#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/tls1.h>
#include <stdbool.h>
#include <getopt.h>
#include <err.h>

#include "user_data.h"
#include "imap.h"

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
            int port = atoi(line + 2);
            printf("DATA: %s\n", line+2);
            if (port != 0) {
                data->message = port;
            }
        } else {
            printf("ERR DATA START: %c\n", *line);
        }
    }
}

int imap_write(struct imap_session *data, const char *msg) {
    data->tag = TAG;
    fprintf(stderr, "C: %s %s\r\n", data->tag, msg);
    return BIO_printf(data->web, "%s %s\r\n", data->tag, msg);
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
    static char line[256];
    int r;
    do {
        r = IMAP_get_line(data->web, line, sizeof(line));
        if (scanner && data) {
            scanner(line, data);
        }
        if (r > 0) {
            fprintf(stderr, "S: %s", line);
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

    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    BIO *web = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(web, IMAP_SERVER);

    BIO_do_connect(web);
    BIO_do_handshake(web);

    session->web = web;
    session->ssl_ctx = ctx;
    session->tag = "*";
    session->msgid = 0;
    session->message = 0;
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

int imap_wait_msg(struct imap_session *session) {
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
            if (!session->message) {
                session->state = LISTEN;
                continue;
            }
            sprintf(cmd, "store %d +flags \\Deleted", session->msgid);
            if (imap_cmd(session, cmd) != OK)
                goto error;
            if (imap_cmd(session, "expunge") != OK)
                goto error;
            session->msgid = 0;
            if (session->message) {
                goto success;
            }
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
    return session->message;
}

int imap_send_msg(struct imap_session *session, int send_msg) {
    char msg[64];
    char cmd[64];
    sprintf(msg, "Subject: %c:%d\r\n\r\n\r\n", session->mode == SERVER ? 's' : 'c', send_msg);
    int mlen = strlen(msg);
    sprintf(cmd, "append xd {%d}", mlen - 4);
    if (imap_cmd(session, cmd) != OK)
        return 1;
    BIO_write(session->web, msg, mlen);
    if (imap_read(session, NULL) != OK)
        return 1;
    return 0;
}