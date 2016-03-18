#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libs/ciphers.h"
#include "libs/exploits.h"
#include "libs/utils.h"

int source_25(unsigned char *ct)
{
	FILE *fp = fopen("files/25.txt", "r");
	unsigned char ecb[4096] = {0}, pt[4096] = {0};
	unsigned char key[] = "YELLOW SUBMARINE", nonce[8] = {0};
	char b64[60];

	int i;
	for (i = 0; fscanf(fp, "%s", b64) == 1; i += 45) {
		base64_str_to_binary(b64, ecb + i);
	}

	// no padding on the plaintext, so we ignore
	// the following return value
	decrypt_AES_ECB(ecb, pt, i - 45, key);

	return AES_CTR(pt, ct, i - 45, get_static_key(), nonce);
}

int edit_25(unsigned char *ct, unsigned char *key, int length, int offset,
		char *newtext)
{
	// too lazy to do this efficiently, just
	// bulk decrypt, replace, encrypt
	unsigned char pt[4096], nonce[8] = {0};
	length = AES_CTR(ct, pt, length, key, nonce);
	
	memcpy(pt + offset, newtext, strlen(newtext)); 

	AES_CTR(pt, ct, length, key, nonce);
	return strlen(newtext);
}

void challenge_25()
{
	unsigned char ct[4096] = {0}, pt[4096];
	int length = source_25(ct);
	
	char newtext[2] = {0};
	newtext[0] = 0x01;
	unsigned char c;
	int i;
	for (i = 0; i < length; ++i) {
		c = ct[i];
		edit_25(ct, get_static_key(), length, i, newtext);
		pt[i] = c ^ ct[i] ^ 0x01;
	}

	print_str((char *)pt);
}

void challenge_26()
{
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	challenge_26();
}
