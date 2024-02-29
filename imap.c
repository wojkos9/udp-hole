#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/tls1.h>
#include <stdbool.h>

#include "user_data.h"

#define TAG "a001"

enum state {
    UNAUTH, AUTH
};

int imap_write(BIO *web, const char *msg) {
    printf("%s %s\r\n", TAG, msg);
    return BIO_printf(web, "%s %s\r\n", TAG, msg);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    BIO *web = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(web, IMAP_SERVER);

    BIO_do_connect(web);
    BIO_do_handshake(web);

    enum state state = UNAUTH;

    int r;
    char buf[256];
    int mid = 0;
    while(1) {
        bool finished = false;
        do {
            puts("read");
            r = BIO_get_line(web, buf, sizeof(buf));
            if (r > 0) {
                write(1, buf, r);
            }
            puts("written");
            switch (state) {
            case UNAUTH:
                if (!strcmp(buf, TAG "OK")) {
                    state = AUTH;
                    finished = true;
                }
                break;
            case AUTH:
                break;
            }
        } while ((r > 0 || BIO_should_retry(web)) && !finished && strcmp(buf, TAG " ") != 0);

        switch (state) {
        case UNAUTH:
            imap_write(web, "login " IMAP_CREDS);
            break;
        }
        ++mid;
    }

    BIO_free_all(web);
    SSL_CTX_free(ctx);

    return 0;
}