#include "rng.h"

uint32_t random_uint32() {
  volatile uint32_t *rng_data_reg = (volatile uint32_t *)(RNG_DATA_REG);

  return *rng_data_reg;
}

int random_from_to(int min, int max) {
  return (min + (abs((int)random_uint32()) % (max - min + 1)));
}