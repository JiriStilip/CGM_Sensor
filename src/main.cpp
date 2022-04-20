#include <Arduino.h>
#include <BLEDevice.h>
#include <BLE2902.h>
#include <SSD1306.h>
#include <CircularBuffer.h>


SSD1306  display(0x3c, 4, 15);

#define CGM_SERVICE_UUID "87f617d1-6c21-461f-b0a5-b5fea2872392"
#define CGM_MEASUREMENT_CHARACTERISTIC_UUID "aa2c4908-64d5-4c89-8ae7-37932f15eadf"
#define CGM_TIME_CHARACTERISTIC_UUID "4f992bbe-675e-4950-9d6c-79acb1cdfa93"

#define SECURITY_SERVICE_UUID "c12f609d-c6b0-49f0-8f17-cba6c45adb8b"
#define SECURITY_VALUE_CHARACTERISTIC_UUID "13494b03-a2da-41f2-8e59-a824d0cee2a5"
#define SECURITY_ACTION_CHARACTERISTIC_UUID "2a1b5b74-97da-4b65-9bfb-dd155d69c8c3"

#define AES_START_REG 0x3FF01000
#define AES_IDLE_REG 0x3FF01004
#define AES_MODE_REG 0x3FF01008
#define AES_KEY_0_REG 0x3FF01010
#define AES_KEY_1_REG 0x3FF01014
#define AES_KEY_2_REG 0x3FF01018
#define AES_KEY_3_REG 0x3FF0101C
#define AES_TEXT_0_REG 0x3FF01030
#define AES_TEXT_1_REG 0x3FF01034
#define AES_TEXT_2_REG 0x3FF01038
#define AES_TEXT_3_REG 0x3FF0103C
#define AES_ENDIAN_REG 0x3FF01040
#define RNG_DATA_REG 0x3FF75144
#define DPORT_PERI_CLK_EN_REG 0x3FF0001C
#define DPORT_PERI_RST_EN_REG 0x3FF00020

#define BLE_SERVER_NAME "CGM Sensor"

#define CGM_INTERVAL 5

#define INVALID_TIME "-1"

#define DH_COMMON_G 2
#define DH_COMMON_P 19

#define INVALID_SEC 8
#define INVALID_SEC_STR "8"
#define PAIR_0 0
#define PAIR_0_STR "0"
#define PAIR_1 1
#define PAIR_1_STR "1"
#define AUTH_0 2
#define AUTH_0_STR "2"
#define AUTH_1 3
#define AUTH_1_STR "3"

#define PIN_LED_R 23


struct CGMeasurement {
  int32_t timeOffset;
  float glucoseValue;
};

float generateValue() {
  float val = sin(millis());
  if (val < 0) {
    val += 1.0;
  }
  val = (val + 5.0) * 18.02;

  return val;
}

uint32_t setNthBitTo(uint32_t reg, int n, bool to) {
  if (to == 0) {
    reg &= ~((uint32_t)1 << n);
  }
  else if (to == 1) {
    reg |= ((uint32_t)1 << n);
  }
  return reg;
}

uint32_t getRandomNumber() {
  volatile uint32_t *rng_data_reg = (volatile uint32_t *)(RNG_DATA_REG);

  uint32_t randomNumber = *rng_data_reg;

  return randomNumber;
}

uint32_t private_key;
uint32_t server_public_key;
uint32_t client_public_key;
uint32_t shared_key = 0;
uint32_t aes_key[4] = { 0 };

char *aes128_endecrypt(char *destination, char *sourcetext, bool decrypt) {
  char text[17] = { '\0' };
  strncpy(text, sourcetext, 16);
  uint32_t text0 = (uint32_t)text[0];
  uint32_t text1 = (uint32_t)text[4];
  uint32_t text2 = (uint32_t)text[8];
  uint32_t text3 = (uint32_t)text[12];

  // Enable AES clock
  volatile uint32_t *dport_peri_clk_en_reg = (volatile uint32_t *)(DPORT_PERI_CLK_EN_REG);
  volatile uint32_t clk_en = *dport_peri_clk_en_reg;
  clk_en = setNthBitTo(clk_en, 0, 1);
  *dport_peri_clk_en_reg = clk_en;
  // Clear reset bit
  volatile uint32_t *dport_peri_rst_en_reg = (volatile uint32_t *)(DPORT_PERI_RST_EN_REG);
  volatile uint32_t rst_en = *dport_peri_rst_en_reg;
/*  rst_en = setNthBitTo(rst_en, 0, 0);
  *dport_peri_rst_en_reg = rst_en;
*/
  *dport_peri_rst_en_reg = (uint32_t)0;       // reset ALL peripherals

  // Initialize AES_MODE_REG
  volatile uint32_t *aes_mode_reg = (volatile uint32_t *)(AES_MODE_REG);
  if (decrypt) {
    *aes_mode_reg = (uint32_t)4;
  }
  else {
    *aes_mode_reg = (uint32_t)0;
  }

  // Initialize AES_KEY_n_REG
  volatile uint32_t *aes_key_0_reg = (volatile uint32_t *)(AES_KEY_0_REG);
  *aes_key_0_reg = aes_key[0];
  volatile uint32_t *aes_key_1_reg = (volatile uint32_t *)(AES_KEY_1_REG);
  *aes_key_1_reg = aes_key[1];
  volatile uint32_t *aes_key_2_reg = (volatile uint32_t *)(AES_KEY_2_REG);
  *aes_key_2_reg = aes_key[2];
  volatile uint32_t *aes_key_3_reg = (volatile uint32_t *)(AES_KEY_3_REG);
  *aes_key_3_reg = aes_key[3];

  // Initialize AES_TEXT_m_REG
  volatile uint32_t *aes_text_0_reg = (volatile uint32_t *)(AES_TEXT_0_REG);
  *aes_text_0_reg = text0;
  volatile uint32_t *aes_text_1_reg = (volatile uint32_t *)(AES_TEXT_1_REG);
  *aes_text_1_reg = text1;
  volatile uint32_t *aes_text_2_reg = (volatile uint32_t *)(AES_TEXT_2_REG);
  *aes_text_2_reg = text2;
  volatile uint32_t *aes_text_3_reg = (volatile uint32_t *)(AES_TEXT_3_REG);
  *aes_text_3_reg = text3;

  // Initialize AES_ENDIAN_REG
  volatile uint32_t *aes_endian_reg = (volatile uint32_t *)(AES_ENDIAN_REG);
  *aes_endian_reg = (uint32_t)0;

  // Write 1 to AES_START_REG
  volatile uint32_t *aes_start_reg = (volatile uint32_t *)(AES_START_REG);
  *aes_start_reg = (uint32_t)1;

  // Wait until AES_IDLE_REG reads 1
  volatile uint32_t *aes_idle_reg = (volatile uint32_t *)(AES_IDLE_REG);
  volatile uint32_t idle = *aes_idle_reg;
  while (idle == 0) {
    idle = *aes_idle_reg;
  }

  // Read results from AES_TEXT_m_REG
  text0 = *aes_text_0_reg;
  text1 = *aes_text_1_reg;
  text2 = *aes_text_2_reg;
  text3 = *aes_text_3_reg;

  // Set reset bit
  rst_en = *dport_peri_rst_en_reg;
  rst_en = setNthBitTo(rst_en, 0, 1);
  *dport_peri_rst_en_reg = rst_en;
  // Disable AES clock
  clk_en = *dport_peri_clk_en_reg;
  clk_en = setNthBitTo(clk_en, 0, 0);
  *dport_peri_clk_en_reg = clk_en;

  memcpy((void *)&destination[0], &text0, sizeof(uint32_t));
  memcpy((void *)&destination[4], &text1, sizeof(uint32_t));
  memcpy((void *)&destination[8], &text2, sizeof(uint32_t));
  memcpy((void *)&destination[12], &text3, sizeof(uint32_t));

  return destination;
}

int timeSinceStart = 0;
int clientLastTime = -1;

CGMeasurement *measurement;

CircularBuffer<CGMeasurement*, 10> buffer;

bool clientConnected = false;
bool clientPaired = false;
bool clientAuthenticated = false;
static char state[8];
int securityAction = INVALID_SEC;
uint32_t checkNum;

BLECharacteristic *cgmMeasurementCharacteristic = new BLECharacteristic(CGM_MEASUREMENT_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ);
BLECharacteristic *cgmTimeCharacteristic = new BLECharacteristic(CGM_TIME_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE);

BLECharacteristic *securityValueCharacteristic = new BLECharacteristic(SECURITY_VALUE_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_NOTIFY);
BLECharacteristic *securityActionCharacteristic = new BLECharacteristic(SECURITY_ACTION_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_READ);

class MyServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      // Serial.println("\nCONNECTED.");
      digitalWrite(PIN_LED_R, HIGH);
      clientConnected = true;
    }

    void onDisconnect(BLEServer* pServer) {
      // Serial.println("\nDISCONNECTED.");
      digitalWrite(PIN_LED_R, LOW);
      clientConnected = false;
      clientAuthenticated = false;
      cgmTimeCharacteristic->setValue(INVALID_TIME);
      clientLastTime = -1;
      sprintf(state, "%s", "INIT");
      pServer->getAdvertising()->start();
      // Serial.println("Advertising started...");
    }
};

bool setValueAfter(int clientLastTime) {
  char measurementMessage[12];

  for (int i = 0; i < buffer.size(); ++i) {
    if (clientLastTime >= buffer[i]->timeOffset) {
      continue;
    }
    sprintf(measurementMessage, "%04d|%6.2f", buffer[i]->timeOffset, buffer[i]->glucoseValue);
    cgmMeasurementCharacteristic->setValue(measurementMessage);
    return true;
  }
  return false;
}

void printCurrentState() {
  char printBuffer[32];

  Serial.println();
  Serial.print("Current state: ");
  Serial.println(state);
  Serial.print("Time since start: ");
  Serial.println(timeSinceStart);
  Serial.print("Client last time: ");
  Serial.println(clientLastTime);
  Serial.print("Security action: ");
  Serial.println(securityAction);
  Serial.print("Client connected: ");
  Serial.println(clientConnected);
  Serial.print("Client paired: ");
  Serial.println(clientPaired);
  Serial.print("Client authenticated: ");
  Serial.println(clientAuthenticated);
  Serial.print("Shared key: ");
  Serial.println(shared_key);
  Serial.print("AES key: ");
  for (int i = 0; i < 4; ++i) {
    Serial.print(aes_key[i]);
  }
  Serial.println();
  Serial.print("Current CGM value: ");
  sprintf(printBuffer, "%04d|%6.2f", buffer.last()->timeOffset, buffer.last()->glucoseValue);
  Serial.println(printBuffer);

  Serial.println("Buffer (time | mg/dL):");
  for (int i = 0; i < buffer.size(); ++i) {
    sprintf(printBuffer, "%02d:%02d | %6.2f", (buffer[i]->timeOffset / 60), (buffer[i]->timeOffset % 60), buffer[i]->glucoseValue);
    Serial.println(printBuffer);
  }
}

void drawScreen(CGMeasurement *measurement, char *message) {
  char printBuffer[128];

  sprintf(printBuffer, "%04d|%6.2f", measurement->timeOffset, measurement->glucoseValue);

  display.clear();
  display.setFont(ArialMT_Plain_16);
  display.drawString(64, 8, printBuffer);
  display.drawHorizontalLine(0, 40, 128);
  display.setFont(ArialMT_Plain_10);
  display.drawStringMaxWidth(64, 42, 128, message);

  display.display();
}

void setup() {
  pinMode(16, OUTPUT);
  digitalWrite(16, LOW);
  delay(50);
  digitalWrite(16, HIGH);

  pinMode(PIN_LED_R, OUTPUT);

  Serial.begin(115200);
  Serial.println();

  display.init();
  display.flipScreenVertically();
  display.setFont(ArialMT_Plain_10);
  display.setTextAlignment(TEXT_ALIGN_CENTER);

  BLEDevice::init(BLE_SERVER_NAME);

  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  // Serial.println("BLE server created...");
  display.clear();
  display.drawStringMaxWidth(64, 22, 128, "BLE server created...");
  display.display();
  delay(1500);

  BLEService *securityService = pServer->createService(SECURITY_SERVICE_UUID);
  securityService->addCharacteristic(securityValueCharacteristic);
  securityService->addCharacteristic(securityActionCharacteristic);
  securityActionCharacteristic->setValue(INVALID_SEC_STR);
  securityService->start();

  BLEService *cgmService = pServer->createService(CGM_SERVICE_UUID);
  cgmService->addCharacteristic(cgmMeasurementCharacteristic);
  cgmService->addCharacteristic(cgmTimeCharacteristic);
  cgmMeasurementCharacteristic->addDescriptor(new BLE2902());
  cgmTimeCharacteristic->setValue(INVALID_TIME);
  cgmService->start();

  pServer->getAdvertising()->start();

  // Serial.println("Advertising started...");
  display.clear();
  display.drawStringMaxWidth(64, 22, 128, "Advertising started...");
  display.display();
  delay(1500);
/*
  Serial.println("Awaiting a client connection to notify...");
  display.clear();
  display.drawStringMaxWidth(64, 22, 128, "Awaiting a client connection to notify...");
  display.display();
  delay(1500);
*/
  display.setFont(ArialMT_Plain_16);

  // generate random key
/*
  for (int i = 0; i < 4; ++i) {
    aes_key[i] = getRandomNumber();
  }
*/
 
  private_key = 5;
  server_public_key = ((int)pow(DH_COMMON_G, private_key)) % DH_COMMON_P;
  sprintf(state, "%s", "INIT");
}

void loop() {
  if (timeSinceStart % CGM_INTERVAL == 0) {
    measurement = new CGMeasurement();
    measurement->timeOffset = timeSinceStart;
    measurement->glucoseValue = generateValue();
    buffer.push(measurement);
  }

  drawScreen(buffer.last(), state);

  // printCurrentState();

  timeSinceStart++;
  if (timeSinceStart >= 3600) {
    timeSinceStart = 0;
  }

  char message[17];

  if (clientConnected) {
    if (clientPaired) {
      if (clientAuthenticated) {
        clientLastTime = atoi((char *)cgmTimeCharacteristic->getValue().c_str());
        if (clientLastTime >= 0) {
          // stav NOTIFY
          sprintf(state, "%s", "NOTIFY");
          if (setValueAfter(clientLastTime)) {
            cgmTimeCharacteristic->setValue(INVALID_TIME);
            cgmMeasurementCharacteristic->notify();
          }
        }
        else {
          // stav READ
          sprintf(state, "%s", "READ");
          sprintf(message, "%04d|%6.2f", buffer.first()->timeOffset, buffer.first()->glucoseValue);
          cgmMeasurementCharacteristic->setValue(message);
        }
      }
      else {
        // stav AUTH
        sprintf(state, "%s", "AUTH");
        securityAction = atoi((char *)securityActionCharacteristic->getValue().c_str());
        switch (securityAction) {
          case INVALID_SEC: 
            checkNum = getRandomNumber() % DH_COMMON_P;
            sprintf(message, "%d", checkNum);
            securityValueCharacteristic->setValue(message);            
            securityActionCharacteristic->setValue(AUTH_0_STR);
            checkNum += shared_key;
            break;
          case AUTH_0: 
            break;
          case AUTH_1: 
            if (atoi((char *)securityValueCharacteristic->getData()) == checkNum) {
              clientAuthenticated = 1;
            }
            securityActionCharacteristic->setValue(INVALID_SEC_STR);
            break;
        }
      }
    }
    else {
      // stav PAIR
      sprintf(state, "%s", "PAIR");
      securityAction = atoi((char *)securityActionCharacteristic->getValue().c_str());
      switch (securityAction) {
        case INVALID_SEC: 
          sprintf(message, "%d", server_public_key);
          securityValueCharacteristic->setValue(message);
          securityActionCharacteristic->setValue(PAIR_0_STR);
          break;
        case PAIR_0: 
          break;
        case PAIR_1: 
          client_public_key = atoi((char *)securityValueCharacteristic->getData());
          shared_key = ((int)pow(client_public_key, private_key)) % DH_COMMON_P;
          for (int i = 0; i < 4; ++i) {
            aes_key[i] = shared_key;
          }
          securityActionCharacteristic->setValue(INVALID_SEC_STR);
          clientPaired = 1;
          break;
      }
    }
  }


  // random number test
/*
  uint32_t nahoda = getRandomNumber();
  Serial.print("Random number: ");
  Serial.println(nahoda);
*/

  // encryption test
/*
  Serial.print("AES key: ");
  for (int i = 0; i < 4; ++i) {
    Serial.print(aes_key[i]);
  }
  Serial.println();
  Serial.print("Plaintext: ");
  char mess[16] = "Encryptmeplease";
  Serial.println(mess);
  char encrypted[17] = { '\0' };
  aes128_endecrypt(encrypted, &mess[0], 0);
  Serial.print("Encrypted: ");
  Serial.println(encrypted);
  Serial.print("Decrypted: ");
  char decrypted[17] = { '\0' };
  aes128_endecrypt(decrypted, encrypted, 1);
  Serial.println(decrypted);
*/
  
  delay(1000);
}