#include <byteswap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

/* padding according to RFC3174 */
int sha1_pad(unsigned char *message, int mlen)
{
	int plen = 64 - (mlen % 64);

	message[mlen] = 0x80;
	int i;
	for (i = 1; i < plen - 8; ++i) {
		message[mlen + i] = 0x00;
	}
	
	uint64_t count = __bswap_64(mlen * 8);
	memcpy(message + mlen + plen - 8, &count, 8);

	return mlen + plen;
}

void sha1(unsigned char *message, int mlen, unsigned char *out)
{
	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c, message, mlen);
	SHA1_Final(out, &c);
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
