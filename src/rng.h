#ifndef RNG_H
#define RNG_H

#include <Arduino.h>

/* ADRESY REGISTRU */

#define RNG_DATA_REG 0x3FF75144


/* FUNKCE RNG */

uint32_t random_uint32();

int random_from_to(int min, int max);

#endif