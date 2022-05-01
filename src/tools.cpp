#include "tools.h"

uint32_t set_nth_bit_to(uint32_t reg, int n, bool to) {
  if (to == 0) {
    reg &= ~((uint32_t)1 << n);
  }
  else if (to == 1) {
    reg |= ((uint32_t)1 << n);
  }
  return reg;
}