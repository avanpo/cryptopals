#include <gmp.h>
#include <stdlib.h>
#include <string.h>

#include "macs.h"
#include "pk.h"
#include "utils.h"

void dh_params(mpz_t p, mpz_t g)
{
	mpz_init(p);
	mpz_init(g);

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

void dh_cleanup(mpz_t p, mpz_t g, mpz_t a, mpz_t A, mpz_t b, mpz_t B)
{
	mpz_clear(p);
	mpz_clear(g);
	mpz_clear(a);
	mpz_clear(A);
	mpz_clear(b);
	mpz_clear(B);
}
