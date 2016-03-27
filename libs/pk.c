#include <gmp.h>
#include <stdlib.h>

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

void dh_serverkeyexchange(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t a, mpz_t A)
{
	dh_params(p, g);
	
	mpz_init(a);
	mpz_init(A);

	mpz_urandomm(a, *state, p);

	mpz_powm(A, g, a, p);
}

void dh_clientkeyexchange(gmp_randstate_t *state, mpz_t p, mpz_t g, mpz_t b, mpz_t B)
{
	mpz_init(b);
	mpz_init(B);

	mpz_urandomm(b, *state, p);

	mpz_powm(B, g, b, p);
}

void dh_finished(mpz_t p, mpz_t public, mpz_t private, mpz_t s)
{
	mpz_init(s);

	mpz_powm(s, public, private, p);
}
