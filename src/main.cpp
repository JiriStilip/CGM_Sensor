#include <Arduino.h>
#include <BLEDevice.h>
#include <BLE2902.h>
#include <SSD1306.h>
#include <CircularBuffer.h>

#include "aes.h"
#include "rng.h"
#include "uuid.h"

#define SENSOR_BLE_NAME "CGM Sensor"

#define DEFAULT_CGM_INTERVAL 5

#define INVALID_TIME "-1"

#define DH_COMMON_G 2
#define DH_COMMON_P 19

#define _INVALID_SEC 8
#define _INVALID_SEC_STR "8"
#define _PAIR_0 0
#define _PAIR_0_STR "0"
#define _PAIR_1 1
#define _PAIR_1_STR "1"
#define _AUTH_0 2
#define _AUTH_0_STR "2"
#define _AUTH_1 3
#define _AUTH_1_STR "3"

#define PIN_OLED_SDA 4
#define PIN_OLED_SCL 15
#define PIN_OLED_RST 16
#define PIN_LED_R 23
#define PIN_POT_0 13

#define PATIENT 1

// objekt integrovaneho displeje
SSD1306  display(0x3c, PIN_OLED_SDA, PIN_OLED_SCL);

// datova struktura mereni a buffer k jejich ukladani
struct CGMeasurement {
  int32_t timeOffset;
  int32_t glucoseValue;
};

CircularBuffer<CGMeasurement, 10> buffer;

// stavy relace a podstavy pro sluzbu zabezpeceni
enum State {INIT, SECURITY, READ, NOTIFY};
enum SecurityState {PAIR_0, PAIR_1, AUTH_0, AUTH_1, READY};


// BLE server, sluzby a jejich charakteristiky
BLEServer *cgmServer;

BLEService *cgmService;
BLECharacteristic *cgmMeasurementCharacteristic;
BLECharacteristic *cgmTimeCharacteristic;

BLEService *securityService;
BLECharacteristic *securityValueCharacteristic;
BLECharacteristic *securityActionCharacteristic;

// klice a hodnoty pro parovani, autentizaci a sifrovani
uint32_t private_key;
uint32_t server_public_key;
uint32_t client_public_key;
uint32_t shared_key = 0;
uint32_t aes_key[4] = { 0 };
uint32_t checkNum;

// promenne potenciometru k nastaveni intervalu mereni
int pot_0;
int cgm_interval = DEFAULT_CGM_INTERVAL;

// cas behu zarizeni
int timeSinceStart = 0;

// promenne pro stav relace
State state = INIT;
SecurityState securityState = PAIR_0;
bool clientConnected = false;
bool clientPaired = false;
bool clientAuthenticated = false;
static char state[8];
int securityAction = INVALID_SEC;
int32_t clientLastTime = -1;

// callback funkce serveru
class CGMServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      digitalWrite(PIN_LED_R, HIGH);
      clientConnected = true;
    }

    void onDisconnect(BLEServer* pServer) {
      digitalWrite(PIN_LED_R, LOW);
      clientConnected = false;
      clientAuthenticated = false;
      cgmTimeCharacteristic->setValue(INVALID_TIME);
      clientLastTime = -1;
      sprintf(state, "%s", "INIT");
      pServer->getAdvertising()->start();
    }
};

/**
 * @brief funkce nastavujici hodnotu charakteristiky mereni nasledujici po zadanem case
 * 
 * @param clientLastTime cas posledniho mereni, ktere ma klient k dispozici
 * @return true nasledujici mereni je k dispozici a bylo nastaveno
 * @return false zadne nasledujici mereni neni k dispozici
 */
bool setValueAfter(int clientLastTime) {
  char measurementMessage[32];

  for (int i = 0; i < buffer.size(); ++i) {
    if (clientLastTime >= buffer[i].timeOffset) {
      continue;
    }
    sprintf(measurementMessage, "%10d|%4d", buffer[i].timeOffset, buffer[i].glucoseValue);
    cgmMeasurementCharacteristic->setValue(measurementMessage);
    return true;
  }
  return false;
}

/**
 * @brief funkce vykreslujici hlavni obrazovku
 * 
 * @param measurement struktura mereni k zobrazeni na displeji
 * @param message zprava k zobrazeni v informacni casti displeje
 */
void drawScreen(CGMeasurement measurement, char *message) {
  char screenBuffer[64];

  display.clear();
  display.setFont(ArialMT_Plain_16);

  sprintf(screenBuffer, "%d", measurement.timeOffset);
  display.drawString(64, 1, screenBuffer);

  sprintf(screenBuffer, "%.2f", (measurement.glucoseValue / 100.0));
  display.drawString(64, 19, screenBuffer);

  display.drawHorizontalLine(0, 38, 128);
  display.setFont(ArialMT_Plain_10);

  display.drawStringMaxWidth(64, 40, 128, message);

  sprintf(screenBuffer, "CGM interval (1 - 10): %d", cgm_interval);
  display.drawStringMaxWidth(64, 52, 128, screenBuffer);

  display.display();
}

void setup() {
  pinMode(PIN_OLED_RST, OUTPUT);
  digitalWrite(PIN_OLED_RST, LOW);
  delay(50);
  digitalWrite(PIN_OLED_RST, HIGH);

  pinMode(PIN_LED_R, OUTPUT);
  pinMode(PIN_POT_0, INPUT);

  Serial.begin(115200);
  Serial.println();

  display.init();
  display.flipScreenVertically();
  display.setFont(ArialMT_Plain_10);
  display.setTextAlignment(TEXT_ALIGN_CENTER);

  display.clear();
  display.drawStringMaxWidth(64, 22, 128, "Setting up...");
  display.display();
  delay(1500);

  BLEDevice::init(SENSOR_BLE_NAME);

  cgmServer = BLEDevice::createServer();
  cgmServer->setCallbacks(new CGMServerCallbacks());

  cgmService = cgmServer->createService(CGM_SERVICE_UUID);

  cgmMeasurementCharacteristic = new BLECharacteristic(CGM_MEASUREMENT_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ);
  cgmMeasurementCharacteristic->addDescriptor(new BLE2902());
  cgmTimeCharacteristic = new BLECharacteristic(CGM_TIME_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE);
  cgmTimeCharacteristic->setValue(INVALID_TIME);

  cgmService->addCharacteristic(cgmMeasurementCharacteristic);
  cgmService->addCharacteristic(cgmTimeCharacteristic);
  cgmService->start();

  securityService = cgmServer->createService(CGM_SECURITY_SERVICE_UUID);

  securityValueCharacteristic = new BLECharacteristic(CGM_SECURITY_VALUE_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE);
  securityActionCharacteristic = new BLECharacteristic(CGM_SECURITY_ACTION_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_READ);
  securityActionCharacteristic->setValue(INVALID_SEC_STR);

  securityService->addCharacteristic(securityValueCharacteristic);
  securityService->addCharacteristic(securityActionCharacteristic);
  securityService->start();

  cgmServer->getAdvertising()->start();

  display.clear();
  display.drawStringMaxWidth(64, 22, 128, "Advertising started...");
  display.display();
  delay(1500);

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
  pot_0 = analogRead(PIN_POT_0);
  cgm_interval = map(pot_0, 0, 4095, 1, 10);

  if (timeSinceStart % cgm_interval == 0) {
    if (PATIENT) {
      String received;
      int32_t time = 0;
      int32_t val = 0;

      Serial.println("STEP");
      do {
        received = Serial.readStringUntil('\n');
        sscanf(received.c_str(), "OK;%d", &time);
      } while (time == 0);

      Serial.println("GET_IG");
      received = Serial.readStringUntil('\n');
      sscanf(received.c_str(), "OK;%d", &val);

      buffer.push(CGMeasurement{time, val});
    }
    else {
      buffer.push(CGMeasurement{timeSinceStart, random_from_to(750, 1500)});
    }   
  }

  drawScreen(buffer.last(), state);

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
          sprintf(message, "%10d|%4d", buffer.first().timeOffset, buffer.first().glucoseValue);
          cgmMeasurementCharacteristic->setValue(message);
        }
      }
      else {
        // stav AUTH
        sprintf(state, "%s", "AUTH");
        securityAction = atoi((char *)securityActionCharacteristic->getValue().c_str());
        switch (securityAction) {
          case INVALID_SEC: 
            checkNum = random_uint32() % DH_COMMON_P;
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

  timeSinceStart++;
  delay(1000);
}