#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libs/exploits.h"
#include "libs/modes.h"
#include "libs/random.h"
#include "libs/utils.h"

size_t source_17(unsigned char *out, unsigned char *iv)
{
	char *base64[] = { "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" };

	unsigned char bytes[128];
	int length = base64_str_to_binary(base64[randn(10)], bytes);

	fill_random_bytes(iv, 16);
	int encrypted_length = encrypt_AES_CBC(bytes, out, length, get_static_key(), iv);

	return encrypted_length;
}

int oracle_17(unsigned char *in, size_t length, unsigned char *iv)
{
	unsigned char *out = malloc(length * sizeof(unsigned char));

	int str_length = decrypt_AES_CBC(in, out, length, get_static_key(), iv);

	if (str_length == 0) {
		return 0;
	} else {
		return 1;
	}
}

void challenge_17()
{
	unsigned char out[1024], plaintext[1024], iv[16];

	int i, length;
	for (i = 0; i < 20; ++i) {
		length = source_17(out, iv);
		break_ciphertext_CBC_padding_oracle(out, plaintext, length, oracle_17, iv);
	}
}

void challenge_18()
{
	char *b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	unsigned char in[128], out[128], nonce[8];
	unsigned char key[17] = "YELLOW SUBMARINE";
	memset(nonce, '\0', 8);

	int length = base64_str_to_binary(b64, in);

	length = AES_CTR(in, out, length, key, nonce);

	print_ascii(out, length);
}

void challenge_19()
{
	FILE *fp = fopen("files/19.txt", "r");

	int lengths[40];
	unsigned char ciphertexts[40][64], plain[64], nonce[8];
	char b64[64];
	memset(nonce, '\0', 8);

	int i, j, k, len;
	for (i = 0; fscanf(fp, "%s", b64) == 1 && i < 40; ++i) {
		len = base64_str_to_binary(b64, plain);
		AES_CTR(plain, ciphertexts[i], len, get_static_key(), nonce);
		lengths[i] = len;
	}

	// start breaking stuff
	unsigned char keystream[64], buffer_cipher[40], buffer_plain[40], plaintexts[40][64];
	memset(keystream, '\0', 64);

	for (i = 0; i < 64; ++i) {
		for (j = 0, k = 0; j < 40; ++j) {
			if (lengths[j] > i) {
				buffer_cipher[k] = ciphertexts[j][i];
				++k;
			}
		}
		keystream[i] = break_ciphertext_single_byte_xor(buffer_cipher, k, buffer_plain);
	}

	keystream[31] = 0x15;
	keystream[33] = 0x3d;
	keystream[34] = 0x6e;
	keystream[35] = 0x38;
	keystream[36] = 0x1d;
	keystream[37] = 0x0c;

	for (i = 0; i < 40; ++i) {
		memset(plaintexts[i], '\0', 64);
		fixed_xor(ciphertexts[i], keystream, lengths[i], plaintexts[i]);
		print_ascii(plaintexts[i], lengths[i]);
	}
}

void challenge_20()
{
	FILE *fp = fopen("files/20.txt", "r");

	int lengths[60];
	unsigned char ciphertexts[60][256], plain[256], nonce[8];
	char b64[256];
	memset(nonce, '\0', 8);

	int i, j, k, len;
	for (i = 0; fscanf(fp, "%s", b64) == 1 && i < 60; ++i) {
		len = base64_str_to_binary(b64, plain);
		AES_CTR(plain, ciphertexts[i], len, get_static_key(), nonce);
		lengths[i] = len;
	}

	// start breaking stuff
	unsigned char keystream[256], buffer_cipher[60], buffer_plain[60], plaintexts[60][256];
	memset(keystream, '\0', 256);

	for (i = 0; i < 256; ++i) {
		for (j = 0, k = 0; j < 60; ++j) {
			if (lengths[j] > i) {
				buffer_cipher[k] = ciphertexts[j][i];
				++k;
			}
		}
		keystream[i] = break_ciphertext_single_byte_xor(buffer_cipher, k, buffer_plain);
	}

	for (i = 0; i < 60; ++i) {
		memset(plaintexts[i], '\0', 256);
		fixed_xor(ciphertexts[i], keystream, lengths[i], plaintexts[i]);
		print_ascii(plaintexts[i], lengths[i]);
	}
}

void challenge_21()
{
	struct mt *rng = init_mtrand();
	int i;
	for (i = 0; i < 20; ++i) {
		printf("%d\n", mtrand(rng));
	}
}

unsigned int routine_22()
{
	struct mt *rng = init_mtrand();

	sleep(randnn(40, 1000));

	int t = time(NULL);
	seed_mtrand(rng, t);
	printf("%d\n", t);

	sleep(randnn(40, 1000));

	int r = mtrand(rng);

	free(rng);
	return r;
}

void challenge_22()
{
	unsigned int r = routine_22();

	struct mt *rng = init_mtrand();
	int t = time(NULL);
	int i;
	for (i = 0; i < 2000; ++i) {
		seed_mtrand(rng, t - i);
		
		if (mtrand(rng) == r) {
			printf("seed: %d\n", t - i);
		}
	}
	free(rng);
}

void challenge_23()
{
	struct mt *rng = init_mtrand();
	seed_mtrand(rng, 0);

	uint32_t state[624];

	int i, l, r;
	l = rand() % 1000;

	for (i = 0; i < l; ++i) {
		r = mtrand(rng);
	}

	for (i = 0; i < 624; ++i) {
		r = mtrand(rng);
		state[i] = untemper(r);
	}

	struct mt *spliced = init_mtrand();
	set_state_mtrand(spliced, state);

	for (i = 0; i < 5; ++i) {
		printf("%d, %d\n", mtrand(rng), mtrand(spliced));
	}
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	challenge_23();
}
