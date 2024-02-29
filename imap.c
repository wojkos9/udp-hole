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

#define TAG "a001"

enum state {
    UNAUTH, CHECK_MAIL, LISTEN, FETCH, SEND, EXIT
};

enum result {
    OK, BAD
};

struct data {
    BIO *web;
    const char *tag;
    int msgid;
    bool message_pending;
    int port;
};

typedef void (*scanner)(char *, struct data *);

#define UNSEEN_TAG "UNSEEN"
void scan_unseen(char *line, struct data *data) {
    char *r = strstr(line, UNSEEN_TAG);
    if (r) {
        int id = atoi(r + sizeof(UNSEEN_TAG));
        if (id) {
            data->msgid = id;
        }
    }
}

#define RECENT_TAG "RECENT"
void scan_recent(char *line, struct data *data) {
    if (strstr(line, RECENT_TAG)) {
        data->message_pending = true;
    }
}

#define SUBJECT_TAG "Subject:"
void scan_subject(char *line, struct data *data) {
    if (strncmp(line, SUBJECT_TAG, sizeof(SUBJECT_TAG) - 1) == 0) {
        int port = atoi(line + sizeof(SUBJECT_TAG) - 1);
        if (port != 0) {
            data->port = port;
        }
    }
}

int imap_write(struct data *data, const char *msg) {
    data->tag = TAG;
    fprintf(stderr, "C: %s %s\r\n", data->tag, msg);
    return BIO_printf(data->web, "%s %s\r\n", data->tag, msg);
}

enum result imap_read(struct data *data, scanner scanner) {
    static char line[256];
    int r;
    do {
        r = BIO_get_line(data->web, line, sizeof(line));
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

enum result imap_cmd(struct data *data, const char *msg) {
    imap_write(data, msg);
    return imap_read(data, NULL);
}

enum mode {
    EMPTY, CLIENT, SERVER
};

int main(int argc, char *argv[]) {
    enum mode mode = EMPTY;
    int send_data = 0;
    char c;
    while ((c = getopt(argc, argv, "c:s")) != -1) {
        switch (c) {
            case 'c':
                mode = CLIENT;
                send_data = atoi(optarg);
                if (!send_data) {
                    errx(1, "Invalid data");
                }
                break;
            case 's':
                mode = SERVER;
                break;
        }
    }

    if (mode == EMPTY) {
        fprintf(stderr, "No mode given");
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    BIO *web = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(web, IMAP_SERVER);

    BIO_do_connect(web);
    BIO_do_handshake(web);

    enum state state = UNAUTH;

    struct data data = {
        .web = web,
        .tag = "*",
        .msgid = 0,
        .port = 0
    };
    imap_read(&data, NULL);
    while(state != EXIT) {
        switch (state) {
        case UNAUTH:
            imap_write(&data, "login " IMAP_CREDS);
            if (imap_read(&data, NULL) != OK)
                goto error;

            state = mode == SERVER ? CHECK_MAIL : SEND;
            break;
        case CHECK_MAIL:
            imap_write(&data, "select xd");
            if (imap_read(&data, scan_unseen) != OK)
                goto error;
            state = data.msgid ? FETCH : LISTEN;
            break;
        case LISTEN:
            sleep(1);
            imap_write(&data, "noop");
            if (imap_read(&data, scan_recent) != OK)
                goto error;
            if (data.message_pending) {
                state = CHECK_MAIL;
            }
            break;
        case FETCH: {
            char cmd[64];
            sprintf(cmd, "fetch %d (BODY[HEADER.FIELDS (Subject)])", data.msgid);
            imap_write(&data, cmd);
            if (imap_read(&data, scan_subject) != OK)
                goto error;
            sprintf(cmd, "store %d +flags /Deleted", data.msgid);
            if (imap_cmd(&data, cmd) != OK)
                goto error;
            if (imap_cmd(&data, "expunge") != OK)
                goto error;
            data.msgid = 0;
            state = data.port ? EXIT : LISTEN;
            break;
        }
        case SEND: {
            char msg[64];
            char cmd[64];
            sprintf(msg, "Subject: %d\r\n\r\n", send_data);
            int mlen = strlen(msg);
            sprintf(cmd, "append xd {%d}", mlen - 4);
            if (imap_cmd(&data, cmd) != OK)
                goto error;
            BIO_write(data.web, msg, mlen);
            if (imap_read(&data, NULL) != OK)
                goto error;
            state = EXIT;
            break;
        }
        default:
            state = EXIT;
            break;
        }
    }
    endloop:

    if (mode == SERVER) {
        printf("Got port %d\n", data.port);
    } else {
        printf("Sent port %d\n", send_data);
    }

    goto free;
    error:
    fputs("Exit due to error", stderr);

    free:
    BIO_free_all(web);
    SSL_CTX_free(ctx);

    return 0;
}