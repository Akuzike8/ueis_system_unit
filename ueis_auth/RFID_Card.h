#ifndef RFID_CARD_H
#define RFID_CARD_H
#include <Arduino.h>
#include <MFRC522.h>

class RFID_CARD {
private:
  MFRC522 mfrc522;
  MFRC522::MIFARE_Key key;
  MFRC522::StatusCode status;
  MFRC522::PICC_Type piccType;
  String id;
  String payload;
  String data;
  int blockNum = 2;
  int length = 0;
  byte bufferLen = 18;
  int blocks = 18;
  char temp[320];
  byte writeBlockData[16];
  byte readBlockData[18];
  bool cardScanned = false;
  int memaddress [36] = {1,2,4,5,6,8,9,10,12,13,14,16,17,18,20,21,22,24,25,26,28,29,30,32,33,34,36,37,38,40,41,42,44,45,46};

  String ReadDataFromBlock(int blockNum, byte readBlockData[]);
  String WriteDataToBlock(int blockNum, byte blockData[]);

public:
  RFID_CARD(int RST_PIN, int SS_PIN);
  void init();
  void scan();
  void write();
  void getCID(byte *buffer, byte bufferSize);
  void getData();
  String decToHexa(int n);
  byte string2ByteArray(char input[]);
  String byteArray2string(byte input[]);
};

#endif