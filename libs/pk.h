#ifndef PK_H
#define PK_H

void dh_params(mpz_t p, mpz_t g);
void dh_serverkeyexchange(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t a, mpz_t A);
void dh_clientkeyexchange(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t b, mpz_t B);
void dh_finished(mpz_t p, mpz_t public, mpz_t private, unsigned char *key);
void dh_kdf(mpz_t s, unsigned char *key);
void dh_kdf_from_ui(unsigned int s, unsigned char *key);
void dh_cleanup(mpz_t p, mpz_t g, mpz_t a, mpz_t A, mpz_t b, mpz_t B);

#endif
