#ifndef MACS_H
#define MACS_H

int sha1_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *hash);

#endif
