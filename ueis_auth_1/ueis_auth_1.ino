#include <SPI.h>
#include <MFRC522.h>
#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>
#include <stdio.h>
#include <stdlib.h>

#define SS_PIN 10  /* Slave Select Pin */
#define RST_PIN 9  /* Reset Pin */
#define TX_PIN 3
#define RX_PIN 2

SoftwareSerial mySerial(RX_PIN, TX_PIN);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;   

// variables
int blockNum = 2;  
byte blockData [16];
int fid = 0;
int p = -1;
char pdu[657];
static char pdu2[657];
static char pd = "";
String id;
String uid = "";
String payload;
String payload2;
byte bufferLen = 20;
byte readBlockData[18];
int incomingByte = 0;
MFRC522::StatusCode status;
bool cardScanned = false;
static char data[300];
int memaddress [36] = {1,2,4,5,6,8,9,10,12,13,14,16,17,18,20,21,22,24,25,26,28,29,30,32,33,34,36,37,38,40,41,42,44,45,46};

// functions avaible
void ReadDataFromBlock(int blockNum, byte readBlockData[]);
void WriteDataToBlock(int blockNum, byte blockData[]);
String decToHexa(int n);
void getCID(byte *buffer, byte bufferSize);
byte string2ByteArray(char input[]); 
void readCharArray();
String readAlphanumericID();
void capture_fingerprint(int p);
int getFingerprintIDez();

void setup() {
  // put your setup code here, to run once:
    Serial.begin(9600);
    /* Initialize SPI bus */
    SPI.begin();
    /* Initialize MFRC522 Module */
    mfrc522.PCD_Init();
    
    finger.begin(57600);

    if (finger.verifyPassword()) {
    } else {
      Serial.println("Did not find fingerprint sensor :(");
      while (1) { delay(1); }
    }

    finger.getParameters();
}

void loop() {

  // put your main code here, to run repeatedly:
  if(Serial.available() > 0)
  {
    incomingByte = Serial.read();

    // initializing key
    for (byte i = 0; i < 6; i++)
    {
      key.keyByte[i] = 0xFF;
    }

    // RFID writing
    if (incomingByte == 49)
    {
      delay(2000);
      readCharArray();
      while(payload2 == "")
      {
         /* Look for new cards */
        /* Reset the loop if no new card is present on RC522 Reader */
      
        if (mfrc522.PICC_IsNewCardPresent())
        {
          /* Select one of the cards */
          if (mfrc522.PICC_ReadCardSerial()) 
          {
            MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
            char pdu[] = "214325dsff.2023-09-22.0xa4f73ae08271a4a2c938698ac9721d108eab2c577c8e428e595a5cf240cd80324ade7c25081953b46847af96acc7a960ff536a6c1ce0bfe2e81b62f0fbc4a49f2dc9443e7970fb721043e0695c512eb6d3c54c75b8d65635dc3d445df9e723ae212c8f4677a2bb92443acbb7ec5b7b861e9b3a7a70aa0b92c05abb4098e26655>";
            
            int start = 0;
            int count = sizeof(pdu);
            int blocks = count / 16;

            /* Call 'WriteDataToBlock' function, which will write data to the block */
            
            for(int i = 0; i < blocks; i++)
            {
              for(int j = 0; j <= 16; j++)
              {
                // writing blockdata
                blockData[j] = pdu[start];
                start++;
              }
              WriteDataToBlock(memaddress[i], blockData);
            }
            start = 0;
            
            /* Read data from the same block */
            for(int i=0; i < blocks; i++)
            {
                ReadDataFromBlock(memaddress[i], readBlockData); 
                
                for(int j = 0; j < 16; j++)
                {
                  // reading blockdata
                  data[start] = readBlockData[j];
                  start++;
                } 
                
            }
            getCID(mfrc522.uid.uidByte, mfrc522.uid.size);
            mfrc522.PICC_HaltA();      // Halt communication with the card
            mfrc522.PCD_StopCrypto1();
          }
        }
     
      }
          
        
    } 


    // RFID Card scanning
    else if (incomingByte == 50) 
    {
      while(payload == "")
      {
        // Check if a card has already been successfully scanned
        if (!cardScanned) 
        {
          // Look for new cards
          if (mfrc522.PICC_IsNewCardPresent()) 
          {
            // Select one of the cards
            if (mfrc522.PICC_ReadCardSerial()) 
            {
              int start = 0;
              int blocks = 18;

              for(int i=0; i < blocks; i++)
              {
                  ReadDataFromBlock(memaddress[i], readBlockData); 
                  for(int j = 0; j < 16; j++)
                  {
                    // reading blockdata
                    data[start] = readBlockData[j];
                    start++;
                  } 
              }
              getCID(mfrc522.uid.uidByte, mfrc522.uid.size);
              mfrc522.PICC_HaltA();      // Halt communication with the card
              mfrc522.PCD_StopCrypto1();
              cardScanned = false;  // Set the flag to indicate a card has been scanned
            }
          }
        }
        else 
        {
          Serial.println("can not scan again!");
        }
      }
      
    } 


    // fingerprint enrollment
    else if (incomingByte == 51) 
    {
      //Serial.println("Fingerprint enrollment");
      delay(1000);
      id = readAlphanumericID();
      fid = id.toInt();
      p = -1;

      // capturing fingerprint
      capture_fingerprint(p);
      
      Serial.println("Remove finger");
      delay(1000);
      p = 0;
      while (p != FINGERPRINT_NOFINGER) {
        p = finger.getImage();
      }

      p = -1;
      Serial.println("Place same finger again");
      delay(50);

      // capturing fingerprint
      capture_fingerprint(p);

      // creating a fingerprint data model
      p = finger.createModel();
      if (p == FINGERPRINT_OK) {
        Serial.println("Prints matched!");
      } 

       // storing fingerprint
      p = finger.storeModel(fid);

      if (p == FINGERPRINT_OK) {
        Serial.println("Stored!");
      } 
      
    }
                   
    // fingerprint scanning
    else if (incomingByte == 52) {
      Serial.println("Fingerprint scanning");
      p = -1;
      delay(1000);
      
      // capturing fingerprint
      capture_fingerprint(p);

      // searching for fingerprint to authenticate
      p = finger.fingerSearch();
      fid = finger.fingerID;
      int confidence = finger.confidence;
      Serial.print("confidence: ");
      Serial.println(confidence);

      Serial.print("fingerprint id: ");
      Serial.println(fid);

      
    }
  }
}


void readCharArray(){
  String input = "";
  delay(100);
    while(Serial.available()){
      delay(1);
      if(Serial.available() > 0){
        char c = Serial.read();
        input += c;
      }
    }
  Serial.println(input);
}


/* RFID and Fingerprint Functions*/
String readAlphanumericID() {
  String input;
  while (Serial.available() >= 2) { // Wait until the input has 64 characters
    char c = Serial.read();
    if (isAlphaNumeric(c)) {
      input += c;
    }
  }
  return input;
}

void getCID(byte *buffer, byte bufferSize) 
{
  int start = 0;
  int blocks = 18;
  

  for (byte i = 0; i < bufferSize; i++) 
  {
    //id += decToHexa(buffer[i]);
     Serial.print(mfrc522.uid.uidByte[i],HEX);
  }
  Serial.print(".");

  for(int i=0; i < blocks; i++)
  {
      ReadDataFromBlock(memaddress[i], readBlockData); 
      for(int j = 0; j < 16; j++)
      {
        // reading blockdata
        if(readBlockData[j] != '\0'){
          char c = readBlockData[j];
          Serial.print(c);
        }
        else{
          break;
        }
      } 
  }
  Serial.println();
}

void WriteDataToBlock(int blockNum, byte blockData[]) 
{
  /* Authenticating the desired data block for write access using Key A */
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
  
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Authentication failed for Write: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    
  }

  
  /* Write data to the block */
  status = mfrc522.MIFARE_Write(blockNum, blockData, 16);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Writing to Block failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    
  }
  
}

void ReadDataFromBlock(int blockNum, byte readBlockData[]) 
{
  /* Authenticating the desired data block for Read access using Key A */
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK)
  {
     Serial.print("Authentication failed for Read: ");
     Serial.println(mfrc522.GetStatusCodeName(status));
     return;
  }
  else
  {
    
  }

  /* Reading data from the Block */
  status = mfrc522.MIFARE_Read(blockNum, readBlockData, &bufferLen);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Reading failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
     
  }
  
}


byte string2ByteArray(char input[]) 
{
  // converting string to byte array
  int loop = 0;
  int i = 0;

  while (input[loop] != '\0') 
  {
    readBlockData[i++] = input[loop++];
  }
  return readBlockData;
}

String decToHexa(int n) 
{
  // char array to store hexadecimal number
  char hexaDeciNum[100];

  // counter for hexadecimal number array
  int i = 0;
  while (n != 0) 
  {
    // temporary variable to store remainder
    int temp = 0;

    // storing remainder in temp variable.
    temp = n % 16;

    // check if temp < 10
    if (temp < 10) {
      hexaDeciNum[i] = temp + 48;
      i++;
    } else {
      hexaDeciNum[i] = temp + 55;
      i++;
    }

    n = n / 16;
  }

  String ans = "";

  // printing hexadecimal number array in reverse order
  for (int j = i - 1; j >= 0; j--)
    ans += hexaDeciNum[j];

  return ans;
}

void capture_fingerprint(int p)
{
  while (p != FINGERPRINT_OK) {
    p = finger.getImage();
    switch (p) {
    case FINGERPRINT_OK:
      //Serial.println("Image taken");
      break;
    case FINGERPRINT_NOFINGER:
      break;
    case FINGERPRINT_PACKETRECIEVEERR:
      Serial.println("Communication error");
      break;
    case FINGERPRINT_IMAGEFAIL:
      Serial.println("Imaging error");
      break;
    default:
      Serial.println("Unknown error");
      break;
    }
  }

  // OK success!

  p = finger.image2Tz(1);
  switch (p) {
    case FINGERPRINT_OK:
      //Serial.println("Image converted");
      break;
    case FINGERPRINT_IMAGEMESS:
      Serial.println("Image too messy");
      return p;
    case FINGERPRINT_PACKETRECIEVEERR:
      Serial.println("Communication error");
      return p;
    case FINGERPRINT_FEATUREFAIL:
      Serial.println("Could not find fingerprint features");
      return p;
    case FINGERPRINT_INVALIDIMAGE:
      Serial.println("Could not find fingerprint features");
      return p;
    default:
      Serial.println("Unknown error");
      return p;
  }
}

int getFingerprintIDez() {
  while(p != FINGERPRINT_OK)
  {
    uint8_t p = finger.getImage();
    switch (p) {
      case FINGERPRINT_OK:
        Serial.println("Image taken");
        break;
      case FINGERPRINT_NOFINGER:
        Serial.println("No finger detected");
        return p;
      case FINGERPRINT_PACKETRECIEVEERR:
        Serial.println("Communication error");
        return p;
      case FINGERPRINT_IMAGEFAIL:
        Serial.println("Imaging error");
        return p;
      default:
        Serial.println("Unknown error");
        return p;
    }

    // OK success!

    p = finger.image2Tz();
    switch (p) {
      case FINGERPRINT_OK:
        Serial.println("Image converted");
        break;
      case FINGERPRINT_IMAGEMESS:
        Serial.println("Image too messy");
        return p;
      case FINGERPRINT_PACKETRECIEVEERR:
        Serial.println("Communication error");
        return p;
      case FINGERPRINT_FEATUREFAIL:
        Serial.println("Could not find fingerprint features");
        return p;
      case FINGERPRINT_INVALIDIMAGE:
        Serial.println("Could not find fingerprint features");
        return p;
      default:
        Serial.println("Unknown error");
        return p;
    }

    // OK converted!
    p = finger.fingerSearch();
    if (p == FINGERPRINT_OK) {
      Serial.println("Found a print match!");
    } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
      Serial.println("Communication error");
      return p;
    } else if (p == FINGERPRINT_NOTFOUND) {
      Serial.println("Did not find a match");
      return p;
    } else {
      Serial.println("Unknown error");
      return p;
    }

    // found a match!
    Serial.print("Found ID #"); Serial.print(finger.fingerID);
    Serial.print(" with confidence of "); Serial.println(finger.confidence);
    return finger.fingerID;
  }
}

