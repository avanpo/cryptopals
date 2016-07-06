#include <gmp.h>
#include <stdlib.h>
#include <string.h>

#include "macs.h"
#include "pk.h"
#include "utils.h"

void dh_params(mpz_t p, mpz_t g)
{
	char p_str[] = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
			"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
			"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
			"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
			"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
			"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
			"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
			"fffffffffffff";

	mpz_init_set_str(p, p_str, 16);
	mpz_init_set_str(g, "2", 10);
}

void dh_keyexchange(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t a, mpz_t A)
{
	mpz_init(a);
	mpz_init(A);

	mpz_urandomm(a, *state, p);

	mpz_powm(A, g, a, p);
}

void dh_finished(mpz_t p, mpz_t public, mpz_t private, unsigned char *key)
{
	mpz_t s;
	mpz_init(s);

	mpz_powm(s, public, private, p);

	dh_kdf(s, key);

	mpz_clear(s);
}

void dh_kdf(mpz_t s, unsigned char *key)
{
	size_t countp;
	unsigned char *rop = mpz_export(NULL, &countp, 1, 1, 1, 0, s);

	unsigned char hash[20];
	sha1(rop, countp, hash);
	memcpy(key, hash, 16);

	free(rop);
}

void dh_kdf_from_ui(unsigned int s, unsigned char *key)
{
	mpz_t s_internal;
	mpz_init_set_ui(s_internal, s);
	
	dh_kdf(s_internal, key);
	mpz_clear(s_internal);
}

void dh_cleanup(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t a, mpz_t A, mpz_t b, mpz_t B)
{
	gmp_randclear(*state);
	free(state);
	mpz_clear(p);
	mpz_clear(g);
	mpz_clear(a);
	mpz_clear(A);
	mpz_clear(b);
	mpz_clear(B);
}

void srp_params(mpz_t N, mpz_t g, mpz_t k)
{
	char N_str[] = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
			"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
			"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
			"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
			"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
			"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
			"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
			"fffffffffffff";

	mpz_init_set_str(N, N_str, 16);

	mpz_init_set_ui(g, 2);
	mpz_init_set_ui(k, 3);
}

void srp_init_server(mpz_t N, mpz_t g, unsigned char *salt, size_t slen, char *password, size_t plen, mpz_t v)
{
	fill_random_bytes(salt, slen);

	unsigned char *buffer = malloc(slen + plen);
	unsigned char hash[32];
	char xH[65];
	memcpy(buffer, salt, slen);
	memcpy(buffer + slen, password, plen);
	sha256(buffer, slen + plen, hash);
	binary_to_hex_str(hash, xH, 32);
	
	mpz_t x;
	mpz_init_set_str(x, xH, 16);

	mpz_init(v);
	mpz_powm(v, g, x, N);

	mpz_clear(x);
	free(buffer);
	memset(hash, 0, 32);
	memset(xH, 0, 65);
}

void srp_client_send(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t a, mpz_t A)
{
	mpz_init(a);
	mpz_init(A);

	mpz_urandomm(a, *state, N);
	mpz_powm(A, g, a, N);
}

void srp_server_send(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t k, mpz_t v, mpz_t b, mpz_t B)
{
	mpz_t kv;

	mpz_init(b);
	mpz_init(B);
	mpz_init(kv);

	mpz_urandomm(b, *state, N);
	mpz_powm(B, g, b, N);

	mpz_mul(kv, k, v);
	mpz_add(B, B, kv);

	mpz_clear(kv);
}

void srp_compute_u(mpz_t A, mpz_t B, mpz_t u)
{
	size_t countpA, countpB;
	unsigned char *rA = mpz_export(NULL, &countpA, 1, 1, 1, 0, A);
	unsigned char *rB = mpz_export(NULL, &countpB, 1, 1, 1, 0, B);

	unsigned char *buffer = malloc(countpA + countpB);
	unsigned char hash[32];
	char uH[65];
	memcpy(buffer, rA, countpA);
	memcpy(buffer + countpA, rB, countpB);
	sha256(buffer, countpA + countpB, hash);
	binary_to_hex_str(hash, uH, 32);

	mpz_init_set_str(u, uH, 16);
	free(rA);
	free(rB);
	free(buffer);
	memset(hash, 0, 32);
	memset(uH, 0, 65);
}

void srp_client_finish(unsigned char *salt, size_t slen, char *password, size_t plen, mpz_t N, mpz_t g, mpz_t k, mpz_t a, mpz_t A, mpz_t B, unsigned char *hmac)
{
	mpz_t u;
	srp_compute_u(A, B, u);

	unsigned char *buffer = malloc(slen + plen);
	unsigned char hash[32];
	char xH[65];
	memcpy(buffer, salt, slen);
	memcpy(buffer + slen, password, plen);
	sha256(buffer, slen + plen, hash);
	binary_to_hex_str(hash, xH, 32);

	mpz_t x;
	mpz_init_set_str(x, xH, 16);

	mpz_t S;
	mpz_init(S);

	mpz_powm(S, g, x, N);
	mpz_mul(S, S, k);
	mpz_sub(S, B, S);
	
	mpz_t aux;
	mpz_init(aux);

	mpz_mul(aux, u, x);
	mpz_add(aux, aux, a);

	mpz_powm(S, S, aux, N);

	size_t countp;
	unsigned char *rop = mpz_export(NULL, &countp, 1, 1, 1, 0, S);

	unsigned char K[32];
	sha256(rop, countp, K);

	sha256_hmac(K, 32, salt, slen, hmac);

	mpz_clear(u);
	mpz_clear(x);
	mpz_clear(S);
	mpz_clear(aux);
	memset(hash, 0, 32);
	memset(xH, 0, 65);
	memset(K, 0, 32);
	free(buffer);
	free(rop);
}

void srp_server_finish(unsigned char *salt, size_t slen, mpz_t N, mpz_t v, mpz_t b, mpz_t A, mpz_t B, unsigned char *hmac)
{
	mpz_t u;
	srp_compute_u(A, B, u);

	mpz_t S;
	mpz_init(S);

	mpz_powm(S, v, u, N);
	mpz_mul(S, S, A);
	mpz_powm(S, S, b, N);

	size_t countp;
	unsigned char *rop = mpz_export(NULL, &countp, 1, 1, 1, 0, S);

	unsigned char K[32];
	sha256(rop, countp, K);

	sha256_hmac(K, 32, salt, slen, hmac);

	mpz_clear(u);
	mpz_clear(S);
	memset(K, 0, 32);
	free(rop);
}

void srp_cleanup(gmp_randstate_t *state, mpz_t N, mpz_t g, mpz_t k, mpz_t v, mpz_t a, mpz_t A, mpz_t b, mpz_t B)
{
	gmp_randclear(*state);
	free(state);
	mpz_clear(N);
	mpz_clear(g);
	mpz_clear(k);
	mpz_clear(v);
	mpz_clear(a);
	mpz_clear(A);
	mpz_clear(b);
	mpz_clear(B);
}
