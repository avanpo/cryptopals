#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>

#include "random.h"
#include "utils.h"

size_t pkcs7_pad(unsigned char *plaintext, size_t length, int block_length)
{
	int i;
	int padding = (length % block_length == 0) ? 16 : block_length - length % block_length;

	for (i = 0; i < padding; ++i) {
		plaintext[length + i] = padding;
	}
	return length + padding;
}

size_t pkcs7_unpad(unsigned char *plaintext, size_t length, int block_length)
{
	int padding = plaintext[length - 1];

	int i, invalid = 0;
	if (length % 16 != 0 || padding < 1 || padding > block_length) {
		++invalid;
	}

	for (i = 0; i < padding && !invalid; ++i) {
		if (plaintext[length - padding + i] != padding) {
			++invalid;
		}
	}

	if (invalid) {
		return 0;
	}

	for (i = length - padding; i < length; ++i) {
		plaintext[i] = 0;
	}
	return length - padding;
}

size_t encrypt_AES_ECB(unsigned char *plaintext, unsigned char *ciphertext, size_t length, const unsigned char *key_str)
{
	AES_KEY key;
	AES_set_encrypt_key(key_str, 128, &key);

	size_t new_length = pkcs7_pad(plaintext, length, 16);

	int i;
	for (i = 0; i < new_length; i += 16) {
		AES_encrypt(&plaintext[i], &ciphertext[i], &key);
	}
	return new_length;
}

size_t decrypt_AES_ECB(unsigned char *ciphertext, unsigned char *plaintext, size_t length, const unsigned char *key_str)
{
	AES_KEY key;
	AES_set_decrypt_key(key_str, 128, &key);

	int i;
	for (i = 0; i < length; i += 16) {
		AES_decrypt(&ciphertext[i], &plaintext[i], &key);
	}

	return pkcs7_unpad(plaintext, length, 16);
}

size_t encrypt_AES_CBC(unsigned char *plaintext, unsigned char *ciphertext, size_t length, const unsigned char *key_str, const unsigned char *iv)
{
	AES_KEY key;
	AES_set_encrypt_key(key_str, 128, &key);

	size_t new_length = pkcs7_pad(plaintext, length, 16);

	unsigned char block[16], xor[16];
	memcpy(xor, iv, 16);

	int i;
	for (i = 0; i < new_length; i += 16) {
		fixed_xor(&plaintext[i], xor, 16, block);
		AES_encrypt(block, &ciphertext[i], &key);
		memcpy(xor, &ciphertext[i], 16);
	}
	return new_length;
}

size_t decrypt_AES_CBC(unsigned char *ciphertext, unsigned char *plaintext, size_t length, const unsigned char *key_str, const unsigned char *iv)
{
	AES_KEY key;
	AES_set_decrypt_key(key_str, 128, &key);

	unsigned char block[16], xor[16];
	memcpy(xor, iv, 16);

	int i;
	for (i = 0; i < length; i += 16) {
		AES_decrypt(&ciphertext[i], block, &key);
		fixed_xor(block, xor, 16, &plaintext[i]);
		memcpy(xor, &ciphertext[i], 16);
	}
	return pkcs7_unpad(plaintext, length, 16);
}

size_t AES_CTR(unsigned char *in, unsigned char *out, size_t length, const unsigned char *key_str, const unsigned char *nonce)
{
	AES_KEY key;
	AES_set_encrypt_key(key_str, 128, &key);

	unsigned char counter[16], keystream[16];
	memcpy(counter, nonce, 8);
	memset(counter + 8, '\0', 8);
	
	int i, l;
	for (i = 0; i < length; i += 16) {
		print_binary(counter, 16);
		AES_encrypt(counter, keystream, &key);
		l = length - i < 16 ? length - i : 16;
		fixed_xor(keystream, in + i, l, out + i);
		(*((uint64_t *) (counter + 8)))++; // counter is machine endian
	}
	return length;
}

size_t MT19937_stream(unsigned char *in, unsigned char *out, size_t length, uint16_t seed)
{
	struct mt *rng = init_mtrand();
	seed_mtrand(rng, seed);

	int i, l, stream;
	for (i = 0; i < length; i += 4) {
		stream = mtrand(rng);
		l = length - i < 4 ? length - i : 4;
		fixed_xor((unsigned char *)&stream, in + i, l, out + i);
	}
	return length;
}
