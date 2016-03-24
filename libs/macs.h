#ifndef MACS_H
#define MACS_H

int sha1_pad_length(int mlen);
int sha1_pad(unsigned char *message, int mlen, int slen);

int sha1_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *hash);

#endif
