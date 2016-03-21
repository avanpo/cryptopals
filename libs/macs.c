#include <stdlib.h>
#include <openssl/sha.h>

void sha1_keyed_mac(unsigned char *message, int mlen, unsigned char *key,
		int klen, unsigned char *out)
{
	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c, key, klen);
	SHA1_Update(&c, message, mlen);
	SHA1_Final(out, &c);
}
