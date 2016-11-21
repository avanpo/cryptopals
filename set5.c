#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libs/ciphers.h"
#include "libs/pk.h"
#include "libs/macs.h"
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

	dh_params(mp, mg);
	dh_keyexchange(state, mp, mg, ma, mA);
	dh_keyexchange(state, mp, mg, mb, mB);

	dh_finished(mp, mB, ma, key1);
	dh_finished(mp, mA, mb, key2);
	
	if (memcmp(key1, key2, 16) == 0) {
		print_str("Shared keys are equal:");
		print_hex(key1, 16);
	}

	dh_cleanup(state, mp, mg, ma, mA, mb, mB);
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
	dh_params(p, g);
	dh_keyexchange(state, p, g, a, A);

	// MITM relays p, g, and p instead of A

	// ClientKeyExchange:
	// Send generated B
	dh_keyexchange(state, p, g, b, B);

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

	dh_cleanup(state, p, g, a, A, b, B);
}

void challenge_35()
{
	gmp_randstate_t *state = gmp_rand();
	mpz_t p, g, a, A, b, B;
	unsigned char server_key[16], client_key[16];
	unsigned char server_ct[256] = {0}, client_ct[256] = {0};
	unsigned char server_iv[16], client_iv[16];
	unsigned char message[128] = "this is a message of 30 bytes.";
	int mlen = 30, ctlen_server, ptlen;
	fill_random_bytes(server_iv, 16);
	fill_random_bytes(client_iv, 16);

	// Negotiate group (server):
	// Send p, g
	dh_params(p, g);

	// MITM replaces g
	mpz_t g_client;
	//mpz_init_set_ui(g_client, 1);
	//mpz_init_set(g_client, p);
	mpz_init(g_client);
	mpz_sub_ui(g_client, p, 1);

	// Negotiate group (client):
	// Send ACK

	// ServerKeyExchange:
	// Sends generated A
	dh_keyexchange(state, p, g, a, A);

	// MITM relays as is

	// ClientKeyExchange:
	// Send generated B
	dh_keyexchange(state, p, g_client, b, B);

	// MITM relays as is

	// Finished (server):
	// Received p from client, sends iv + encrypted message
	dh_finished(p, B, a, server_key);
	ctlen_server = encrypt_AES_CBC(message, server_ct, mlen, server_key, server_iv);

	// MITM relays as is

	// Finished (client):
	// Received p from server, sends iv + encrypted message
	dh_finished(p, A, b, client_key);
	encrypt_AES_CBC(message, client_ct, mlen, client_key, client_iv);

	// MITM relays as is

	// For g = 1:
	//   Server key should now be kdf(1), since
	//   B^a = (1^b)^a = 1
	//   Client key unknown if A cannot be modified
	// For g = p:
	//   Server key should now be kdf(0), since
	//   B^a = 0^a = 0
	//   Client key unknown if A cannot be modified
	// For g = p - 1:
	//   Server key should now be kdf(1) 75% of the time,
	//     and kdf(p-1) 25% of the time, since
	//   B^a = ((p-1)^b)^a mod p = 1     if a*b even
	//                           = p - 1 if a*b odd
	//   Client key unknown if A cannot be modified
	unsigned char mitm_key[16];
	unsigned char pt[256] = {0};
	dh_kdf_from_ui(1, mitm_key);
	ptlen = decrypt_AES_CBC(server_ct, pt, ctlen_server, mitm_key, server_iv);
	if (ptlen == 0) {
		dh_kdf(g_client, mitm_key);
		ptlen = decrypt_AES_CBC(server_ct, pt, ctlen_server, mitm_key, server_iv);
	}
	print_str("Recovered plaintext from server message:");
	print_binary(pt, ptlen);

	dh_cleanup(state, p, g, a, A, b, B);
	mpz_clear(g_client);
}

void challenge_36()
{
	gmp_randstate_t *state = gmp_rand();

	unsigned char salt[16];
	char password[] = "hunter2";
	size_t slen = 16, plen = 7;

	// Agree on N, g, k, I (email), P (password).
	mpz_t N, g, k;
	srp_params(N, g, k);

	// Server initialization. Generates M (salt), v.
	mpz_t v;
	srp_init_server(N, g, salt, slen, password, plen, v);

	// Client sends I, A = g^a mod N.
	mpz_t a, A;
	srp_client_send(state, N, g, a, A);

	// Server sends M, B = kv + g^b mod N.
	mpz_t b, B;
	srp_server_send(state, N, g, k, v, b, B);

	// Both calculate u.
	mpz_t u;
	srp_compute_u(A, B, u);

	// Client finishes, calculates HMAC-SHA256(K, M),
	// where K = SHA256((B - k * g^x)^(a + u * x) % N).
	unsigned char client_hmac[32];
	srp_client_finish(salt, slen, password, plen, N, g, k, a, B, u, client_hmac);

	// Server finishes, calculates the same. For K, it
	// uses K = SHA256((A * v^u)^b % N).
	unsigned char server_hmac[32];
	srp_server_finish(salt, slen, N, v, b, A, u, server_hmac);
	
	// Verify.
	printf("Client:\n");
	print_hex(client_hmac, 32);
	printf("Server:\n");
	print_hex(server_hmac, 32);

	srp_cleanup(state, N, g, k, v, a, A, b, B, u);
}

void challenge_37()
{
	gmp_randstate_t *state = gmp_rand();

	unsigned char salt[16];
	char password[] = "hunter2";
	size_t slen = 16, plen = 7;

	// Agree on N, g, k, I (email), P (password).
	mpz_t N, g, k;
	srp_params(N, g, k);

	// Server initialization. Generates M (salt), v.
	mpz_t v;
	srp_init_server(N, g, salt, slen, password, plen, v);

	// Client sends I, A = 0, N, 2*N, etc. This ensures K
	// can be calculated without knowing the password.
	mpz_t a, A;
	//mpz_init_set_ui(A, 0);
	mpz_init_set(A, N);
	mpz_mul_ui(A, A, 2);

	// Server sends M, B = kv + g^b mod N.
	mpz_t b, B;
	srp_server_send(state, N, g, k, v, b, B);

	// Both calculate u.
	mpz_t u;
	srp_compute_u(A, B, u);

	// Client calculates HMAC-SHA256(K, M), using knowledge
	// that A = 0, N, etc. Therefore, S = 0.
	unsigned char K[32];
	unsigned char client_hmac[32];
	mpz_init_set_ui(a, 0);
	size_t countp;
	unsigned char *rop = mpz_export(NULL, &countp, 1, 1, 1, 0, a);
	sha256(rop, countp, K);
	sha256_hmac(K, 32, salt, 16, client_hmac);

	// Server finishes, calculates the same. For K, it
	// uses K = SHA256((A * v^u)^b % N).
	unsigned char server_hmac[32];
	srp_server_finish(salt, slen, N, v, b, A, u, server_hmac);
	
	// Verify.
	printf("Client:\n");
	print_hex(client_hmac, 32);
	printf("Server:\n");
	print_hex(server_hmac, 32);

	srp_cleanup(state, N, g, k, v, a, A, b, B, u);
}

void challenge_38()
{
	gmp_randstate_t *state = gmp_rand();

	unsigned char salt[16];
	char password[] = "hunter2";
	size_t slen = 16, plen = 7;

	// Agree on N, g, k, I (email), P (password).
	mpz_t N, g, k;
	srp_params(N, g, k);

	// MITM Server initialization.
	// Do not know the password, so cannot generate v.
	slen = 0;

	// Client sends I, A = g^a mod N.
	mpz_t a, A;
	srp_client_send(state, N, g, a, A);

	// MITM Server sends M, B = g^b mod N,
	// u (random 128 bit num). Doesn't really matter.
	mpz_t b, B, u;
	srp_server_send_simple(state, N, g, b, B, u);

	// Client finishes, calculates HMAC-SHA256(K, M),
	// where K = SHA256(B^(a + u * x) % N).
	unsigned char client_hmac[32];
	srp_client_finish_simple(salt, slen, password, plen, N, g, a, B, u, client_hmac);

	// MITM posing as server performs a dictionary
	// attack on client's password.
	char *dict[8];
	dict[0] = "a";
	dict[1] = "dictionary";
	dict[2] = "attack";
	dict[3] = "on";
	dict[4] = "hunter2";
	dict[5] = "and";
	dict[6] = "possibly";
	dict[7] = "others";
	
	int i;
	for (i = 0; i < 8; ++i) {
		unsigned char server_hmac[32];
		mpz_t v;
		srp_init_server(N, g, salt, slen, dict[i], strlen(dict[i]), v);
		srp_server_finish(salt, slen, N, v, b, A, u, server_hmac);
		mpz_clear(v);
		if (memcmp(client_hmac, server_hmac, 32) == 0) {
			printf("Found valid password:\n%s\n", dict[i]);
		}
	}
	printf("\nDictionary search ended.\n");

	srp_cleanup(state, N, g, k, NULL, a, A, b, B, u);
}

void challenge_39()
{
	mpz_t n, e, d;
	char *p_str = "38b689c351cf329d5efd5676b";
	char *q_str = "54060a750a88d007bd41db2cb";

	rsa_keygen(p_str, q_str, n, e, d);

	size_t pt_len = 32, ct_len = 0;
	unsigned char pt[200] = "yellow submarineyellow submarine";
	unsigned char ct[200] = {0};

	mpz_out_str(stdout, 16, n);
	printf("\n");
	mpz_out_str(stdout, 16, e);
	printf("\n");
	mpz_out_str(stdout, 16, d);
	printf("\n");

	rsa_encrypt(pt, pt_len, ct, ct_len, n, e);

	memset(pt, 0, 32);

	rsa_decrypt(ct, ct_len, pt, pt_len, n, d);

	printf("Plaintext length: %ld\n", pt_len);
	print_binary(pt, pt_len);
}

int main(int argc, char *argv[])
{
	srand(time(NULL));

	challenge_39();
}
