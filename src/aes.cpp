#include "aes.h"

void aes128_endecrypt(char *destination, char *sourcetext, uint32_t *aes_key, bool decrypt) {
  char text[17] = { '\0' };

  strncpy(text, sourcetext, 16);
  uint32_t text0 = ((uint32_t *)text)[0];
  uint32_t text1 = ((uint32_t *)text)[1];
  uint32_t text2 = ((uint32_t *)text)[2];
  uint32_t text3 = ((uint32_t *)text)[3];

  // Zapnuti perifernich hodin AES
  volatile uint32_t *dport_peri_clk_en_reg = (volatile uint32_t *)(DPORT_PERI_CLK_EN_REG);
  *dport_peri_clk_en_reg = set_nth_bit_to(*dport_peri_clk_en_reg, 0, 1);

  // Vycisteni reset bitu AES hodin
  volatile uint32_t *dport_peri_rst_en_reg = (volatile uint32_t *)(DPORT_PERI_RST_EN_REG);
  *dport_peri_rst_en_reg = set_nth_bit_to(*dport_peri_clk_en_reg, 0, 0);

  // Inicializace AES_MODE_REG - sifrovani nebo desifrovani
  volatile uint32_t *aes_mode_reg = (volatile uint32_t *)(AES_MODE_REG);
  if (decrypt) {
    *aes_mode_reg = (uint32_t)4;
  }
  else {
    *aes_mode_reg = (uint32_t)0;
  }

  // Inicializace AES_KEY_n_REG - nastaveni klice
  volatile uint32_t *aes_key_0_reg = (volatile uint32_t *)(AES_KEY_0_REG);
  *aes_key_0_reg = aes_key[0];
  volatile uint32_t *aes_key_1_reg = (volatile uint32_t *)(AES_KEY_1_REG);
  *aes_key_1_reg = aes_key[1];
  volatile uint32_t *aes_key_2_reg = (volatile uint32_t *)(AES_KEY_2_REG);
  *aes_key_2_reg = aes_key[2];
  volatile uint32_t *aes_key_3_reg = (volatile uint32_t *)(AES_KEY_3_REG);
  *aes_key_3_reg = aes_key[3];

  // Inicializace AES_TEXT_m_REG - predani textu
  volatile uint32_t *aes_text_0_reg = (volatile uint32_t *)(AES_TEXT_0_REG);
  *aes_text_0_reg = text0;
  volatile uint32_t *aes_text_1_reg = (volatile uint32_t *)(AES_TEXT_1_REG);
  *aes_text_1_reg = text1;
  volatile uint32_t *aes_text_2_reg = (volatile uint32_t *)(AES_TEXT_2_REG);
  *aes_text_2_reg = text2;
  volatile uint32_t *aes_text_3_reg = (volatile uint32_t *)(AES_TEXT_3_REG);
  *aes_text_3_reg = text3;

  // Inicializace AES_ENDIAN_REG - nastaveni endianity
  volatile uint32_t *aes_endian_reg = (volatile uint32_t *)(AES_ENDIAN_REG);
  *aes_endian_reg = (uint32_t)0;

  // Zapis 1 do AES_START_REG
  volatile uint32_t *aes_start_reg = (volatile uint32_t *)(AES_START_REG);
  *aes_start_reg = (uint32_t)1;

  // Cekani dokud AES_IDLE_REG neni 1
  volatile uint32_t *aes_idle_reg = (volatile uint32_t *)(AES_IDLE_REG);
  while (*aes_idle_reg == 0) {
  }

  // Precteni vysledku z AES_TEXT_m_REG
  text0 = *aes_text_0_reg;
  text1 = *aes_text_1_reg;
  text2 = *aes_text_2_reg;
  text3 = *aes_text_3_reg;

  // Nastaveni reset bitu AES hodin
  *dport_peri_rst_en_reg = set_nth_bit_to(*dport_peri_rst_en_reg, 0, 1);

  // Vypnuti perifernich hodin AES
  *dport_peri_clk_en_reg = set_nth_bit_to(*dport_peri_clk_en_reg, 0, 0);

  // Prekopirovani textu do zadaneho pole
  memcpy((void *)&destination[0], &text0, sizeof(uint32_t));
  memcpy((void *)&destination[4], &text1, sizeof(uint32_t));
  memcpy((void *)&destination[8], &text2, sizeof(uint32_t));
  memcpy((void *)&destination[12], &text3, sizeof(uint32_t));
}

void aes128_encrypt(char *dest, char *src, uint32_t *key) {
    aes128_endecrypt(dest, src, key, 0);
}

void aes128_decrypt(char *dest, char *src, uint32_t *key) {
    aes128_endecrypt(dest, src, key, 1);
}