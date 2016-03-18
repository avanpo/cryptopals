#include <stdlib.h>
#include <stdint.h>

#include "random.h"

static void twist(struct mt *mt);

struct mt {
	int index;
	uint32_t state[624];
};

struct mt *init_mtrand()
{
	struct mt *mt = calloc(1, sizeof(struct mt));
	seed_mtrand(mt, 5489);
	return mt;
}

void seed_mtrand(struct mt *mt, int seed)
{
	mt->index = 624;
	mt->state[0] = seed;

	int i;
	for (i = 1; i < 624; ++i) {
		mt->state[i] = 0xffffffff & (0x6c078965 * (mt->state[i - 1] ^
					(mt->state[i - 1] >> 30)) + i);
	}
}

void set_state_mtrand(struct mt *mt, uint32_t *st)
{
	int i;
	for (i = 0; i < 624; ++i) {
		mt->state[i] = st[i];
	}
}

unsigned int mtrand(struct mt *mt)
{
	if (mt->index >= 624) {
		twist(mt);
	}

	return temper(mt->state[mt->index++]);
}

unsigned int temper(uint32_t y)
{
	y = y ^ (y >> 11);
	y = y ^ ((y << 7) & 0x9d2c5680);
	y = y ^ ((y << 15) & 0xefc60000);
	y = y ^ (y >> 18);

	return (unsigned int)y;
}

uint32_t untemper(uint32_t x)
{
	x = (x & 0xffffc000) + ((x ^ (x >> 18)) & 0x00003fff);
	int x_l30 = (x & 0x00007fff) + ((x ^ ((x << 15) & 0xefc60000)) & 0x3fff8000);
	x = x_l30 + ((x ^ ((x_l30 << 15) & 0xefc60000)) & 0xc0000000);
	int x_l14 = (x & 0x0000007f) + ((x ^ ((x << 7) & 0x9d2c5680)) & 0x00003f80);
	int x_l21 = x_l14 + ((x ^ ((x_l14 << 7) & 0x9d2c5680)) & 0x001fc000);
	int x_l28 = x_l21 + ((x ^ ((x_l21 << 7) & 0x9d2c5680)) & 0x0fe00000);
	x = x_l28 + ((x ^ ((x_l28 << 7) & 0x9d2c5680)) & 0xf0000000);
	int x_m21 = (x & 0xffe00000) + ((x ^ (x >> 11)) & 0x001ffc00);
	x = x_m21 + ((x ^ (x_m21 >> 11)) & 0x000003ff);

	return x;
}

static void twist(struct mt *mt)
{
	int i;
	for (i = 0; i < 624; ++i) {
		unsigned long long x = (mt->state[i] & 0x80000000) + (mt->state[(i + 1) % 624] & 0x7fffffff);
		mt->state[i] = mt->state[(i + 397) % 624] ^ (x >> 1);
		if ((x % 2) != 0) {
			mt->state[i] ^= 0x9908b0df;
		}
	}
	mt->index = 0;
}
