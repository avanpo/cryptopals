#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libs/ciphers.h"
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
	mpz_t mp, mg, ma, mb, mA, mB;
	unsigned char key1[16], key2[16];

	dh_serverkeyexchange(state, mp, mg, ma, mA);
	dh_clientkeyexchange(state, mp, mg, mb, mB);

	dh_finished(mp, mB, ma, key1);
	dh_finished(mp, mA, mb, key2);
	
	if (memcmp(key1, key2, 16) == 0) {
		print_str("Shared keys are equal:");
		print_hex(key1, 16);
	}

	dh_cleanup(mp, mg, ma, mA, mb, mB);
}

void challenge_34()
{
	gmp_randstate_t *state = gmp_rand();
	mpz_t p, g, a, A, b, B;
	unsigned char server_key[16], client_key[16];
	unsigned char server_ct[256] = {0}, client_ct[256] = {0};
	unsigned char server_iv[16], client_iv[16];
	unsigned char message[128] = "this is a message of 30 bytes.";
	int mlen = 30, ctlen_server, ctlen_client, ptlen;
	fill_random_bytes(server_iv, 16);
	fill_random_bytes(client_iv, 16);

	// ServerKeyExchange:
	// Sends generated p, g, A
	dh_serverkeyexchange(state, p, g, a, A);

	// MITM relays p, g, and p instead of A

	// ClientKeyExchange:
	// Send generated B
	dh_clientkeyexchange(state, p, g, b, B);

	// MITM relays p instead of B

	// Finished (server):
	// Received p from client, sends iv + encrypted message
	dh_finished(p, p, a, server_key);
	ctlen_server = encrypt_AES_CBC(message, server_ct, mlen, server_key, server_iv);

	// MITM relays as is

	// Finished (client):
	// Received p from server, sends iv + encrypted message
	dh_finished(p, p, b, client_key);
	ctlen_client = encrypt_AES_CBC(message, client_ct, mlen, client_key, client_iv);

	// MITM relays as is

	// Key should now be kdf(0), since
	// p mod p = 0 and 0^a = 0^b = 0
	unsigned char mitm_key[16];
	unsigned char pt[256] = {0};
	dh_kdf_from_ui(0, mitm_key);
	ptlen = decrypt_AES_CBC(server_ct, pt, ctlen_server, mitm_key, server_iv);
	print_str("Recovered plaintext from server message:");
	print_binary(pt, ptlen);
	memset(pt, 0, 256);
	ptlen = decrypt_AES_CBC(client_ct, pt, ctlen_client, mitm_key, client_iv);
	print_str("Recovered plaintext from client message:");
	print_binary(pt, ptlen);
}

int main(int argc, char *argv[])
{
	challenge_34();
}
