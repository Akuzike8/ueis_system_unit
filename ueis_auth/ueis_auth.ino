#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>
#include <stdio.h>
#include <stdlib.h>
#include <SPI.h>
#include "RFID_Card.h"
#include "Fingerprint.h"

#define RST_PIN 9  // Define the reset pin (can be changed)
#define SS_PIN 10  // Define the SS pin (can be changed)
#define TX_PIN 3
#define RX_PIN 2
#define LED_PIN 6

SoftwareSerial mySerial(RX_PIN,TX_PIN);
RFID_CARD card = RFID_CARD(SS_PIN, RST_PIN);  // Create card instance
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

int incomingByte = 0;

void setup() {
  // Initiating
  pinMode(LED_PIN, OUTPUT);
  Serial.begin(9600);
  SPI.begin();  // Initialize SPI bus
  card.init();
  finger.begin(57600);
  fingerprint::init(finger);
}

void loop() {
  digitalWrite(LED_PIN, HIGH);
  
  if (Serial.available() > 0)
  {
    incomingByte = Serial.read();

    if (incomingByte == 49)
     {
      // RFID writing
      card.write();
    } 
    else if (incomingByte == 50) {
      // RFID Card scanning
      card.scan();
    } 
    else if (incomingByte == 51) {
      // Fingerprint enrollment
      fingerprint::enroll(finger);
    }
    else if (incomingByte == 52) {
      // Fingerprint scanning
      fingerprint::verify(finger);
    }
  }
}
