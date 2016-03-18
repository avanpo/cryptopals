#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "modes.h"
#include "oracles.h"
#include "utils.h"

unsigned char *get_static_key()
{
	static unsigned char static_key[16];

	static int init = 0;
	if (!init) {
		srand(0);
		fill_random_bytes(static_key, 16);
		init = 1;
	}
	return static_key;
}

/*int get_random_length()
{
	static int length;

	static int init = 0;
	if (!init) {
		srand(2);
		length = rand() % 16;
		init = 1;
	}
	return length;
}

int oracle_12(unsigned char *in, size_t length, unsigned char *out)
{
	char *base64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	unsigned char secret[185];
	size_t secret_length = base64_str_to_binary(base64_secret, secret);

	unsigned char *plaintext = malloc((length + secret_length + 16) * sizeof(unsigned char));
	memcpy(plaintext, in, length);
	memcpy(plaintext + length, secret, secret_length);

	int encrypted_length =  encrypt_AES_ECB(plaintext, out, length + secret_length, get_random_key());

	free(plaintext);
	return encrypted_length;
}

size_t oracle_13(char *email, unsigned char *out)
{
	char *enc = profile_for(email);

	int encrypted_length = encrypt_AES_ECB((unsigned char *)enc, out, strlen(enc),
			get_random_key());

	free(enc);
	return encrypted_length;
}

void receiver_13(unsigned char *in, size_t length)
{
	unsigned char *out = malloc(length * sizeof(unsigned char));

	int str_length = decrypt_AES_ECB(in, out, length, get_random_key());

	struct dictionary *profile = kv_parse((char *)out);

	print_dictionary(profile);

	dictionary_destroy(profile);
	free(out);
}

char *profile_for(char *email)
{
	char *start = "email=";

	// sanitize email input
	int i;
	for (i = 0; email[i] != '\0'; ++i) {
		if (email[i] == '=' || email[i] == '&') {
			email[i] = '_';
		}
	}

	char *between = "&uid=";

	// generate uid
	int id = (rand() % 900) + 100;
	char uid[4];
	sprintf(uid, "%d", id);

	// role
	char *end = "&role=user";

	int enc_length = 6 + strlen(email) + 5 + strlen(uid) + 10 + 1;
	char *enc = calloc(enc_length, sizeof(char));

	memcpy(enc, start, 6);
	memcpy(enc + 6, email, strlen(email));
	memcpy(enc + 6 + strlen(email), between, 5);
	memcpy(enc + 6 + strlen(email) + 5, uid, strlen(uid));
	memcpy(enc + 6 + strlen(email) + 5 + strlen(uid), end, 10);
	enc[enc_length - 1] = '\0';

	return enc;
}

int oracle_14(unsigned char *in, size_t length, unsigned char *out)
{
	char *base64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	unsigned char secret[184];
	size_t secret_length = base64_str_to_binary(base64_secret, secret);

	int random_length = get_random_length();

	unsigned char *plaintext = malloc((random_length + length + secret_length + 16) *
			sizeof(unsigned char));
	memcpy(plaintext, get_random_iv(), random_length);
	memcpy(plaintext + random_length, in, length);
	memcpy(plaintext + random_length + length, secret, secret_length);

	int encrypted_length = encrypt_AES_ECB(plaintext, out,
			random_length + length + secret_length, get_random_key());

	free(plaintext);
	return encrypted_length;
}

int oracle_16(unsigned char *in, size_t length, unsigned char *out)
{
	char *prepend = "comment1=cooking%20MCs;userdata=";
	char *append = ";comment2=%20like%20a%20pound%20of%20bacon";
	int pre_length = 32, ap_length = 42;

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

	int encrypted_length = encrypt_AES_CBC((unsigned char *)encoding, out,
			j + ap_length, get_random_key(), get_random_iv());

	free(encoding);
	return encrypted_length;
}

void receiver_16(unsigned char *in, size_t length)
{
	unsigned char *out = malloc(length * sizeof(unsigned char));

	int str_length = decrypt_AES_CBC(in, out, length, get_random_key(),
			get_random_iv());

	unsigned char target[13] = ";admin=true;";

	int i, j;
	for (i = 0, j = 0; i < str_length; ++i) {
		if (out[i] == target[j]) {
			++j;
			if (j > 11) {
				free(out);
				printf("true\n");
				return;
			}
		} else {
			j = 0;
		}
	}

	free(out);
	printf("false\n");
	return;
} */
