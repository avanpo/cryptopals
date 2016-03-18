#ifndef MODES_H
#define MODES_H

#define ECB 1
#define CBC 2

size_t pkcs7_pad(unsigned char *plaintext, size_t length, int block_length);
size_t pkcs7_unpad(unsigned char *plaintext, size_t length, int block_length);

size_t encrypt_AES_ECB(unsigned char *plaintext, unsigned char *ciphertext, size_t length, const unsigned char *key_str);
size_t decrypt_AES_ECB(unsigned char *ciphertext, unsigned char *plaintext, size_t length, const unsigned char *key_str);
size_t encrypt_AES_CBC(unsigned char *plaintext, unsigned char *ciphertext, size_t length, const unsigned char *key_str, const unsigned char *iv);
size_t decrypt_AES_CBC(unsigned char *ciphertext, unsigned char *plaintext, size_t length, const unsigned char *key_str, const unsigned char *iv);
size_t AES_CTR(unsigned char *in, unsigned char *out, size_t length, const unsigned char *key_str, const unsigned char *nonce);

#endif
