# CC=mipsel-buildroot-linux-uclibc-gcc
CC=gcc

udp-hole: udp-hole.c imap.c socket.c stun.c b64.c
	$(CC) -o $@ $^ -lssl -lcrypto