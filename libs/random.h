#ifndef RANDOM_H
#define RANDOM_H

struct mt;

struct mt *init_mtrand();
void seed_mtrand(struct mt *mt, int seed);
void set_state_mtrand(struct mt *mt, uint32_t *st);
unsigned int mtrand(struct mt *mt);

unsigned int temper(uint32_t y);
uint32_t untemper(uint32_t x);

#endif
