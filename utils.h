#ifndef HEADER_UTILS_H
#define HEADER_UTILS_H

#define ECB 1
#define CBC 2

struct dictionary {
	struct dictionary_entry *head;
	struct dictionary_entry *tail;
	int length;
};

struct dictionary_entry {
	struct dictionary *dict;
	struct dictionary_entry *next;
	char *key;
	char *value;
};

struct dictionary *dictionary_create();
void dictionary_add(struct dictionary *dict, char *key, char *value);
void dictionary_destroy(struct dictionary *dict);

struct dictionary *kv_parse(char *str);

unsigned char hex_to_nibble(char hex);
char nibble_to_hex(unsigned char nibble);
size_t hex_str_to_binary(const char *hex, unsigned char *bin);
void binary_to_hex_str(const unsigned char *bin, char *hex, size_t length);

unsigned char base64_to_binary(char base64);
size_t base64_str_to_binary(const char *base64, unsigned char *bin);

void print_binary(unsigned char *bin, size_t length);
void print_hex(unsigned char *bin, size_t length);
void print_ascii(unsigned char *bin, size_t length);
void print_str(char *str);
void print_dictionary(struct dictionary *dict);
void print(int val);

int count_high_bits(unsigned char byte);

double score_english(unsigned char *a, int length);

void fixed_xor(const unsigned char *a, const unsigned char *b, size_t length, unsigned char *out);

size_t pkcs7_pad(unsigned char *plaintext, size_t length, int block_length);
size_t pkcs7_unpad(unsigned char *plaintext, size_t length, int block_length);

size_t encrypt_AES_ECB(unsigned char *plaintext, unsigned char *ciphertext, size_t length, const unsigned char *key_str);
size_t decrypt_AES_ECB(unsigned char *ciphertext, unsigned char *plaintext, size_t length, const unsigned char *key_str);
size_t encrypt_AES_CBC(unsigned char *plaintext, unsigned char *ciphertext, size_t length, const unsigned char *key_str, const unsigned char *iv);
size_t decrypt_AES_CBC(unsigned char *ciphertext, unsigned char *plaintext, size_t length, const unsigned char *key_str, const unsigned char *iv);
size_t AES_CTR(unsigned char *in, unsigned char *out, size_t length, const unsigned char *key_str, const unsigned char *nonce);

void fill_random_bytes(unsigned char *buffer, size_t length);

#endif
