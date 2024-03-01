udp-hole: udp-hole.c imap.c stun.c
	gcc -o $@ $^ -lssl -lcrypto