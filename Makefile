udp-hole: udp-hole.c imap.c stun.c b64.c
	gcc -o $@ $^ -lssl -lcrypto