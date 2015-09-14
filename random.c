#include <stdlib.h>
#include <stdio.h>

#include "random.h"

static void twist(struct mt *mt);

struct mt {
	int index;
	unsigned long long state[624];
};

struct mt *init_mtrand(int seed)
{
	struct mt *mt = calloc(1, sizeof(struct mt));

	mt->index = 624;
	mt->state[0] = seed;

	int i;
	for (i = 1; i < 624; ++i) {
		mt->state[i] = 0xffffffff & (0x6c078965 * (mt->state[i - 1] ^ (mt->state[i - 1] >> 30))) + i;
	}

	return mt;
}

void seed_mtrand(struct mt *mt, int seed)
{
	mt->index = 624;
	mt->state[0] = seed;

	int i;
	for (i = 1; i < 624; ++i) {
		mt->state[i] = 0xffffffff & (0x6c078965 * (mt->state[i - 1] ^ (mt->state[i - 1] >> 30))) + i;
	}
}

void set_state_mtrand(struct mt *mt, unsigned long long *st)
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

static unsigned int temper(unsigned long long y)
{
	y = y ^ (y >> 11);
	y = y ^ ((y << 7) & 0x9d2c5680);
	y = y ^ ((y << 15) & 0xefc60000);
	y = y ^ (y >> 18);

	return (unsigned int)y;
}

static unsigned long long untemper(unsigned int x)
{
	unsigned long long y = (unsigned long long)x;

	y = 
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
