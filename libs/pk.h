#ifndef PK_H
#define PK_H

void dh_params(mpz_t p, mpz_t g);
void dh_keyexchange(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t a, mpz_t A);
void dh_finished(mpz_t p, mpz_t public, mpz_t private, unsigned char *key);
void dh_kdf(mpz_t s, unsigned char *key);
void dh_kdf_from_ui(unsigned int s, unsigned char *key);
void dh_cleanup(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t a, mpz_t A, mpz_t b, mpz_t B);

void srp_params(mpz_t N, mpz_t g, mpz_t k);
void srp_init_server(mpz_t N, mpz_t g, unsigned char *salt, size_t slen, char *password, size_t plen, mpz_t v);
void srp_client_send(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t a, mpz_t A);
void srp_server_send(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t k, mpz_t v, mpz_t b, mpz_t B);
void srp_server_send_simple(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t b, mpz_t B, mpz_t u);
void srp_compute_u(mpz_t A, mpz_t B, mpz_t u);
void srp_client_finish(unsigned char *salt, size_t slen, char *password, size_t plen, mpz_t N, mpz_t g, mpz_t k, mpz_t a, mpz_t B, mpz_t u, unsigned char *hmac);
void srp_client_finish_simple(unsigned char *salt, size_t slen, char *password, size_t plen, mpz_t N, mpz_t g, mpz_t a, mpz_t B, mpz_t u, unsigned char *hmac);
void srp_server_finish(unsigned char *salt, size_t slen, mpz_t N, mpz_t v, mpz_t b, mpz_t A, mpz_t u, unsigned char *hmac);
void srp_cleanup(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t k, mpz_t v, mpz_t a, mpz_t A, mpz_t b, mpz_t B, mpz_t u);

void rsa_keygen(char *p_str, char *q_str, mpz_t n, mpz_t e, mpz_t d);
void rsa_encrypt(unsigned char *m_bin, size_t m_len, unsigned char *c_bin, size_t c_len, mpz_t n, mpz_t e);
void rsa_decrypt(unsigned char *c_bin, size_t c_len, unsigned char *m_bin, size_t m_len, mpz_t n, mpz_t d);

#endif
