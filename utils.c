#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>

#include "utils.h"

struct dictionary *dictionary_create()
{
	struct dictionary *dict = calloc(1, sizeof(struct dictionary));
	return dict;
}

struct dictionary_entry *dictionary_search(struct dictionary *dict, char *key)
{
	struct dictionary_entry *entry = dict->head;
	while (entry != NULL) {
		if (strcmp(key, entry->key) == 0) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

void dictionary_add(struct dictionary *dict, char *key, char *value)
{
	struct dictionary_entry *entry;
	
	// replace key value if exists
	entry = dictionary_search(dict, key);
	if (entry != NULL) {
		entry->value = value;
		return;
	}

	// else create new entry
	entry = calloc(1, sizeof(struct dictionary_entry));
	entry->dict = dict;
	entry->next = NULL;
	entry->key = key;
	entry->value = value;

	if (dict->length == 0) {
		dict->head = entry;
	} else {
		dict->tail->next = entry;
	}
	dict->length++;
	dict->tail = entry;
}

void dictionary_destroy(struct dictionary *dict)
{
	struct dictionary_entry *entry = dict->head, *tmp = dict->head;
	while (entry != NULL) {
		tmp = entry->next;
		free(entry);
		entry = tmp;
	}
	free(dict);
}

struct dictionary *kv_parse(char *str)
{
	struct dictionary *dict = dictionary_create();

	char *delim = "=&";
	char *token = strtok(str, delim);
	char *key, *value;

	while (token) {
		key = token;
		token = strtok(NULL, delim);
		value = token;
		dictionary_add(dict, key, value);
		token = strtok(NULL, delim);
	}
	return dict;
}

unsigned char hex_to_nibble(char hex)
{
	if (hex <= '9')
		return hex - '0';
	if (hex >= 'A' && hex <= 'Z')
		return hex - 'A' + 10;
	return hex - 'a' + 10;
}

char nibble_to_hex(unsigned char nibble)
{
	if (nibble <= 9)
		return nibble + '0';
	return nibble + 'a' - 10;
}

size_t hex_str_to_binary(const char *hex, unsigned char *bin)
{
	int i = 0, j = 0, len = strlen(hex);
	if (len % 2 != 0)
		bin[i++] = hex_to_nibble(hex[j++]);

	for (; hex[j] != 0; ++i, j += 2)
		bin[i] = (hex_to_nibble(hex[j]) << 4) + hex_to_nibble(hex[j + 1]);

	return i;
}

void binary_to_hex_str(const unsigned char *bin, char *hex, size_t length)
{
	int i, j;
	for (i = 0, j = 0; i < length; ++i, j += 2) {
		hex[j] = nibble_to_hex(bin[i] >> 4);
		hex[j + 1] = nibble_to_hex(bin[i] & 0x0F);
	}
	hex[j] = 0;
}

unsigned char base64_to_binary(char base64)
{
	if (base64 >= 'A' && base64 <= 'Z')
		return base64 - 'A';
	if (base64 >= 'a' && base64 <= 'z')
		return base64 - 'a' + 26;
	if (base64 >= '0' && base64 <= '9')
		return base64 - '0' + 52;
	if (base64 == '+')
		return 62;
	if (base64 == '/')
		return 63;
	if (base64 == '=')
		return 0xFF;
	return 0;
}

size_t base64_str_to_binary(const char *base64, unsigned char *bin)
{
	int i, j;
	unsigned char x1, x2, x3, x4;
	for (i = 0, j = 0; base64[i] != 0; i += 4) {
		x1 = base64_to_binary(base64[i]);
		x2 = base64_to_binary(base64[i + 1]);
		x3 = base64_to_binary(base64[i + 2]);
		x4 = base64_to_binary(base64[i + 3]);
		bin[j++] = (x1 << 2) | (x2 >> 4);
		if (x3 == 0xFF)
			break;
		bin[j++] = (x2 << 4) | (x3 >> 2);
		if (x4 == 0xFF)
			break;
		bin[j++] = (x3 << 6) | x4;
	}
	return j;
}

void print_binary(unsigned char *bin, size_t length)
{
	int i, j;
	for (i = 0; i < length;){
		for (j = 0; j < 16; ++j, ++i) {
			if (i < length) {
				printf("%.2x ", bin[i]);
			} else {
				printf("   ");
			}
		}
		i -= 16;
		printf("  ");
		for (j = 0; j < 16; ++j, ++i) {
			if (i < length && (bin[i] < 32 || bin[i] > 126)) {
				putchar('.');
			} else if (i < length) {
				putchar(bin[i]);
			}
		}
		printf("\n");
	}
}

void print_hex(unsigned char *bin, size_t length)
{
	int i;
	for (i = 0; i < length; ++i) {
		printf("%.2x ", bin[i]);
	}
	printf("\n");
}

void print_ascii(unsigned char *bin, size_t length)
{
	int i;
	for (i = 0; i < length; ++i) {
		if (bin[i] < 32 || bin[i] > 126) {
			putchar('.');
		} else {
			putchar(bin[i]);
		}
	}
	printf("\n");
}

void print_str(char *str)
{
	printf("%s\n", str);
}

void print_dictionary(struct dictionary *dict)
{
	struct dictionary_entry *entry = dict->head;
	while (entry) {
		printf("%s=%s\n", entry->key, entry->value);
		entry = entry->next;
	}
}

void print(int val)
{
	printf("%d\n", val);
}

int count_high_bits(unsigned char byte)
{
	const char high_bits[] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
	return high_bits[byte & 0x0f] + high_bits[byte >> 4];
}

double score_english(unsigned char *a, int length)
{
	double score = 0.0;
	double freq_table[26] = { 6.53, 1.26, 2.23, 3.28, 10.27, 1.98, 1.62, 4.98, 5.67,
				0.10, 0.56, 3.32, 2.03, 5.71, 6.16, 1.50, 0.08, 4.99,
				5.32, 7.52, 2.28, 0.8, 1.70, 0.14, 1.43, 0.05 };

	int i;
	for (i = 0; i < length; ++i) {
		if (a[i] >= 'A' && a[i] <= 'Z') {
			score += freq_table[a[i] - 'A'];
		} else if (a[i] >= 'a' && a[i] <= 'z') {
			score += freq_table[a[i] - 'a'];
		} else if (a[i] == ' ') {
			score += 18.29;
		} else if (a[i] == ',' || a[i] == '.') {
			score += 1.00;
		} else if (a[i] == '\n' || a[i] == '?' || a[i] == '!') {
			score += 0.25;
		} else if (a[i] < 32 || a[i] > 126) {
			score -= 15.00;
		}
	}
	return score / length;
}

void fixed_xor(const unsigned char *a, const unsigned char *b, size_t length, unsigned char *out)
{
	int i;
	for (i = 0; i < length; ++i) {
		out[i] = a[i] ^ b[i];
	}
}

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
		invalid = 1;
	}
	for (i = 0; i < padding && !invalid; ++i) {
		if (plaintext[length - padding + i] != padding) {
			invalid = 1;
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
	
	int i;
	for (i = 0; i < length; i += 16) {
		AES_encrypt(counter, keystream, &key);
		if (length - i < 16) {
			fixed_xor(keystream, in + i, length - i, out + i);
		} else {
			fixed_xor(keystream, in + i, 16, out + i);
		}
		(*((uint64_t *) (counter + 8)))++; // counter is machine endian
	}
	return length;
}

void fill_random_bytes(unsigned char *buffer, size_t length)
{
	int i;
	for (i = 0; i < length; ++i) {
		buffer[i] = rand() % 256;
	}
}
