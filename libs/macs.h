#ifndef MACS_H
#define MACS_H

int sha1_pad_length(int mlen);
int sha1_pad(unsigned char *message, int mlen, int slen);
int md4_pad(unsigned char *message, int mlen, int slen);

void sha1(const unsigned char *message, int mlen, unsigned char *out);
void sha256(const unsigned char *message, int mlen, unsigned char *out);

int sha1_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *hash);

void md4_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *out);

void sha1_hmac(unsigned char *key, int klen, unsigned char *message, int mlen,
		unsigned char *out);
void sha256_hmac(unsigned char *key, int klen, unsigned char *message, int mlen,
		unsigned char *out);

#endif
