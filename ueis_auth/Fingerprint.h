#ifndef Fingerprint_H
#define Fingerprint_H
#include <Arduino.h>
#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>

namespace fingerprint
{
  void init(Adafruit_Fingerprint finger);
  void capture(int p);
  void enroll(Adafruit_Fingerprint finger);
  void verify(Adafruit_Fingerprint finger);
  int getId();
}
#endif