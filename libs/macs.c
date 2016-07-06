#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md4.h>

/* Calculate sha1 padding length based on message
 * length. */
int sha1_pad_length(int mlen)
{
	int l = 64 - (mlen % 64);
	if (l <= 9) {
		l += 64;
	}
	return l;
}

/* Padding according to RFC3174.
 *   mlen: length of the message
 *   slen: length of any prepended secret
 * returns: new length of message buffer */
int sha1_pad(unsigned char *message, int mlen, int slen)
{
	int plen = sha1_pad_length(slen + mlen);

	message[mlen] = 0x80;
	int i;
	for (i = 1; i < plen - 8; ++i) {
		message[mlen + i] = 0x00;
	}
	
	uint64_t count = htobe64((mlen + slen) * 8);
	memcpy(message + mlen + plen - 8, &count, 8);

	return mlen + plen;
}

/* Padding according to RFC1186. */
int md4_pad(unsigned char *message, int mlen, int slen)
{
	int plen = sha1_pad_length(slen + mlen);

	message[mlen] = 0x80;
	int i;
	for (i = 1; i < plen - 8; ++i) {
		message[mlen + i] = 0x00;
	}
	
	uint64_t count = htole64((mlen + slen) * 8);
	memcpy(message + mlen + plen - 8, &count, 8);

	return mlen + plen;
}

void sha1(const unsigned char *message, int mlen, unsigned char *out)
{
	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c, message, mlen);
	SHA1_Final(out, &c);
}

void sha256(const unsigned char *message, int mlen, unsigned char *out)
{
	SHA256_CTX c;
	SHA256_Init(&c);
	SHA256_Update(&c, message, mlen);
	SHA256_Final(out, &c);
}

void sha1_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *out)
{
	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c, key, klen);
	SHA1_Update(&c, message, mlen);
	SHA1_Final(out, &c);
}

void md4_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *out)
{
	MD4_CTX c;
	MD4_Init(&c);
	MD4_Update(&c, key, klen);
	MD4_Update(&c, message, mlen);
	MD4_Final(out, &c);
}

/* NOTE: doesn't support keys larger than block size,
 * such keys should be hashed before use */
void sha1_hmac(unsigned char *key, int klen, unsigned char *message, int mlen,
		unsigned char *out)
{
	int i;
	unsigned char tmp[20], block[64] = {0};

	SHA_CTX c1, c2;
	SHA1_Init(&c1);
	SHA1_Init(&c2);

	for (i = 0; i < 64; ++i) {
		block[i] = 0x36;
		if (i < klen) {
			block[i] ^= key[i];
		}
	}

	SHA1_Update(&c1, block, 64);
	SHA1_Update(&c1, message, mlen);
	SHA1_Final(tmp, &c1);

	for (i = 0; i < 64; ++i) {
		block[i] = 0x5c;
		if (i < klen) {
			block[i] ^= key[i];
		}
	}

	SHA1_Update(&c2, block, 64);
	SHA1_Update(&c2, tmp, 20);
	SHA1_Final(out, &c2);
}

/* NOTE: doesn't support keys larger than block size,
 * such keys should be hashed before use */
void sha256_hmac(unsigned char *key, int klen, unsigned char *message, int mlen,
		unsigned char *out)
{
	int i;
	unsigned char tmp[32], block[64] = {0};

	SHA256_CTX c1, c2;
	SHA256_Init(&c1);
	SHA256_Init(&c2);

	for (i = 0; i < 64; ++i) {
		block[i] = 0x36;
		if (i < klen) {
			block[i] ^= key[i];
		}
	}

	SHA256_Update(&c1, block, 64);
	SHA256_Update(&c1, message, mlen);
	SHA256_Final(tmp, &c1);

	for (i = 0; i < 64; ++i) {
		block[i] = 0x5c;
		if (i < klen) {
			block[i] ^= key[i];
		}
	}

	SHA256_Update(&c2, block, 64);
	SHA256_Update(&c2, tmp, 32);
	SHA256_Final(out, &c2);
}
