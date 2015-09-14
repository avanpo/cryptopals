#ifndef HEADER_RANDOM_H
#define HEADER_RANDOM_H

struct mt;

struct mt *init_mtrand(int seed);
void seed_mtrand(struct mt *mt, int seed);
void set_state_mtrand(struct mt *mt, unsigned long long *st);
unsigned int mtrand(struct mt *mt);

unsigned int temper(unsigned long long y);
unsigned long long untemper(unsigned int x);

#endif
