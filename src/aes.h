#ifndef AES_H
#define AES_H

#include <Arduino.h>
#include "tools.h"

/* ADRESY REGISTRU */

#define AES_START_REG 0x3FF01000
#define AES_IDLE_REG 0x3FF01004

#define AES_MODE_REG 0x3FF01008
#define AES_ENDIAN_REG 0x3FF01040

#define AES_KEY_0_REG 0x3FF01010
#define AES_KEY_1_REG 0x3FF01014
#define AES_KEY_2_REG 0x3FF01018
#define AES_KEY_3_REG 0x3FF0101C

#define AES_TEXT_0_REG 0x3FF01030
#define AES_TEXT_1_REG 0x3FF01034
#define AES_TEXT_2_REG 0x3FF01038
#define AES_TEXT_3_REG 0x3FF0103C

#define DPORT_PERI_CLK_EN_REG 0x3FF0001C
#define DPORT_PERI_RST_EN_REG 0x3FF00020


/* FUNKCE AES */

void aes128_encrypt(char *dest, char *src, uint32_t *key);

void aes128_decrypt(char *dest, char *src, uint32_t *key);

#endif