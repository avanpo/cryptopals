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

int source_26(unsigned char *in, size_t length, unsigned char *out)
{
	char prepend[] = "comment1=cooking%20MCs;userdata=";
	char append[] = ";comment2=%20like%20a%20pound%20of%20bacon";
	int pre_length = strlen(prepend), ap_length = strlen(append);

	char *encoding = malloc((pre_length + 3 * length + ap_length) * sizeof(char));

	memcpy(encoding, prepend, pre_length);
	int i, j;
	for (i = 0, j = pre_length; i < length; ++i, ++j) {
		if (in[i] == ';' || in[i] == '=') {
			encoding[j++] = '"';
			encoding[j++] = in[i];
			encoding[j] = '"';
		} else {
			encoding[j] = in[i];
		}
	}
	memcpy(encoding + j, append, ap_length);

	unsigned char nonce[8] = {0};
	int encrypted_length = AES_CTR((unsigned char *)encoding, out,
			j + ap_length, get_static_key(), nonce);

	free(encoding);
	return encrypted_length;
}

int receiver_26(unsigned char *in, size_t length)
{
	unsigned char *out = malloc(length * sizeof(unsigned char));

	unsigned char nonce[8] = {0};
	int str_length = AES_CTR(in, out, length, get_static_key(), nonce);

	unsigned char target[13] = ";admin=true;";

	int i, j;
	for (i = 0, j = 0; i < str_length; ++i) {
		if (out[i] == target[j]) {
			++j;
			if (j > 11) {
				free(out);
				return 1;
			}
		} else {
			j = 0;
		}
	}

	free(out);
	return 0;
}

void challenge_26()
{
	unsigned char input[11] = ":admin<true";
	unsigned char output[512] = {0};

	int len = source_26(input, 11, output);

	output[32] ^= 0x01;
	output[38] ^= 0x01;

	int result = receiver_26(output, len);
	if (result) {
		print_str("admin priveleges");
	} else {
		print_str("stay back, plebeian");
	}
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	challenge_26();
}
