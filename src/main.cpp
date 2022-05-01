#include <Arduino.h>
#include <BLEDevice.h>
#include <BLE2902.h>
#include <SSD1306.h>
#include <CircularBuffer.h>

#include "aes.h"
#include "rng.h"
#include "uuid.h"

SSD1306  display(0x3c, 4, 15);

#define BLE_SERVER_NAME "CGM Sensor"

#define DEFAULT_CGM_INTERVAL 5

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
#define PIN_POT_0 13

#define PATIENT 0


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

uint32_t private_key;
uint32_t server_public_key;
uint32_t client_public_key;
uint32_t shared_key = 0;
uint32_t aes_key[4] = { 0 };

int pot_0;

int cgm_interval = DEFAULT_CGM_INTERVAL;
int timeSinceStart = 0;
int clientLastTime = -1;

CircularBuffer<CGMeasurement, 10> buffer;

bool clientConnected = false;
bool clientPaired = false;
bool clientAuthenticated = false;
static char state[8];
int securityAction = INVALID_SEC;
uint32_t checkNum;

BLECharacteristic *cgmMeasurementCharacteristic = new BLECharacteristic(CGM_MEASUREMENT_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ);
BLECharacteristic *cgmTimeCharacteristic = new BLECharacteristic(CGM_TIME_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE);

BLECharacteristic *securityValueCharacteristic = new BLECharacteristic(CGM_SECURITY_VALUE_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_NOTIFY);
BLECharacteristic *securityActionCharacteristic = new BLECharacteristic(CGM_SECURITY_ACTION_CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_READ);

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
    if (clientLastTime >= buffer[i].timeOffset) {
      continue;
    }
    sprintf(measurementMessage, "%04d|%6.2f", buffer[i].timeOffset, buffer[i].glucoseValue);
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
  sprintf(printBuffer, "%04d|%6.2f", buffer.last().timeOffset, buffer.last().glucoseValue);
  Serial.println(printBuffer);

  Serial.println("Buffer (time | mg/dL):");
  for (int i = 0; i < buffer.size(); ++i) {
    sprintf(printBuffer, "%02d:%02d | %6.2f", (buffer[i].timeOffset / 60), (buffer[i].timeOffset % 60), buffer[i].glucoseValue);
    Serial.println(printBuffer);
  }
}

void drawScreen(CGMeasurement measurement, char *message) {
  char printBuffer[128];

  sprintf(printBuffer, "%04d|%6.2f", measurement.timeOffset, measurement.glucoseValue);

  display.clear();
  display.setFont(ArialMT_Plain_16);
  display.drawString(64, 8, printBuffer);
  display.drawHorizontalLine(0, 40, 128);
  display.setFont(ArialMT_Plain_10);
  display.drawStringMaxWidth(64, 42, 128, message);

  sprintf(printBuffer, "CGM interval set to: %d s", cgm_interval);
  display.drawStringMaxWidth(64, 54, 128, printBuffer);

  display.display();
}

void setup() {
  pinMode(16, OUTPUT);
  digitalWrite(16, LOW);
  delay(50);
  digitalWrite(16, HIGH);

  pinMode(PIN_LED_R, OUTPUT);
  pinMode(PIN_POT_0, INPUT);

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

  BLEService *securityService = pServer->createService(CGM_SECURITY_SERVICE_UUID);
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
  pot_0 = analogRead(PIN_POT_0);
  cgm_interval = map(pot_0, 0, 4095, 1, 10);

  if (timeSinceStart % cgm_interval == 0) {
    if (PATIENT) {
      String received;
      int time = 0;
      int val = 0;

      Serial.println("STEP");
      received = Serial.readString();
      sscanf(received.c_str(), "OK;%d", &time);

      Serial.println("GET_IG");
      received = Serial.readString();
      sscanf(received.c_str(), "OK;%d", &val);

      buffer.push(CGMeasurement{((time % 86400) / 60), (float)(val / 100.00)});
    }
    else {
      buffer.push(CGMeasurement{timeSinceStart, generateValue()});
    }   
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
          sprintf(message, "%04d|%6.2f", buffer.first().timeOffset, buffer.first().glucoseValue);
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


  delay(1000);
}