#ifndef ORACLES_H
#define ORACLES_H

typedef int (*oracle_t)(unsigned char *, size_t, unsigned char *);

unsigned char *get_static_key();
/*int get_random_length();

// This oracle uses ECB mode, appends a secret text to the input, and
// uses a constant unknown key.
int oracle_12(unsigned char *in, size_t length, unsigned char *out);

// This oracle takes an email and generates an ECB encrypted kv encoding
// of the profile object.
size_t oracle_13(char *email, unsigned char *out);
void receiver_13(unsigned char *in, size_t length);
static char *profile_for(char *email);

// This oracle is the same as oracle_12 but prepends a random amount of
// random bytes to every plaintext.
int oracle_14(unsigned char *in, size_t length, unsigned char *out);

// This oracle encrypts some sanitized input in the middle of a string
// using CBC mode.
int oracle_16(unsigned char *in, size_t length, unsigned char *out);
void receiver_16(unsigned char *in, size_t length);

// This source encrypts one of several unknown strings using CBC mode.
// The oracle returns true or false depending on the padding validity.
size_t source_17(unsigned char *out, unsigned char *iv);
int oracle_17(unsigned char *in, size_t length, unsigned char *iv);
*/
#endif
