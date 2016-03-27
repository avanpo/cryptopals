#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libs/pk.h"
#include "libs/utils.h"

void challenge_33()
{
	srand(time(NULL));
	int p = 37;
	int g = 5;

	int a = randn(37);
	int A = modexp(g, a, p);

	int b = randn(37);
	int B = modexp(g, b, p);

	int s = modexp(B, a, p);
	if (s == modexp(A, b, p)) {
		printf("Shared secrets are equal: %d\n", s);
	}

	gmp_randstate_t *state = gmp_rand();
	mpz_t mp, mg, ma, mb, mA, mB, ms1, ms2;

	dh_serverkeyexchange(state, mp, mg, ma, mA);
	dh_clientkeyexchange(state, mp, mg, mb, mB);

	dh_finished(mp, mB, ma, ms1);
	dh_finished(mp, mA, mb, ms2);
	
	if (mpz_cmp(ms1, ms2) == 0) {
		print_str("Shared secrets are equal:");
		gmp_printf("%Zx\n", ms1);
	}
}

int main(int argc, char *argv[])
{
	challenge_33();
}
