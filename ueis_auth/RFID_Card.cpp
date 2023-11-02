
#include "RFID_Card.h"

RFID_CARD::RFID_CARD(int RST_PIN, int SS_PIN) 
{
  this->mfrc522 = MFRC522(RST_PIN, SS_PIN);
}

void RFID_CARD::init() 
{
  this->mfrc522.PCD_Init();
  for (byte i = 0; i < 6; i++) 
  {
    this->key.keyByte[i] = 0xFF;
  }
}

void RFID_CARD::scan() 
{
  // Check if a card has already been successfully scanned
  
    // Look for new cards
  if (mfrc522.PICC_IsNewCardPresent()) 
  {
    // Select one of the cards
    if (mfrc522.PICC_ReadCardSerial()) 
    {
      this->getCID(mfrc522.uid.uidByte, mfrc522.uid.size);

      mfrc522.PICC_HaltA();      // Halt communication with the card
      mfrc522.PCD_StopCrypto1();  // Set the flag to indicate a card has been scanned
    }
  }
  
   
 
}

void RFID_CARD::getData(){
  char inputs[320];
  this->payload = "";
  boolean end = false;
  char rc;

  while(true)
  {
    if(end == true)
    {
      this->payload.toCharArray(temp, this->length + 2);
      break;
    }

    while(Serial.available() > 0 )
    {
      rc = Serial.read();
      if(rc != '>')
      {
        inputs[this->length] = rc;
        this->payload += rc;
        this->length++;
      }
      else
      {
        end = true;
        break;
      }
      
    }


  }
}

void RFID_CARD::getCID(byte *buffer, byte bufferSize) {
  int start = 0;
  int blocks = 19;
  

  for (byte i = 0; i < bufferSize; i++) 
  {
    //id += decToHexa(buffer[i]);
     Serial.print(mfrc522.uid.uidByte[i],HEX);
  }
  Serial.print(":");

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

void RFID_CARD::write() 
{
  // Check if a card has already been successfully scanned
  if (!this->cardScanned) 
  {
    // Look for new cards
    if (mfrc522.PICC_IsNewCardPresent()) 
    {
      Serial.println(1);
      // Select one of the cards
      if (mfrc522.PICC_ReadCardSerial()) 
      {
        this->piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
        int start = 0;
        int lastBlock = 0;
        getData();
        
        for(int i = 0; i < 4; i++)
        {
          for(int j = 0; j < 16; j++)
          {
            this->writeBlockData[j] = temp[start];
            start++;
          }
          this->WriteDataToBlock(this->memaddress[i], this->writeBlockData);
        }

        start = 0;

        this->getCID(mfrc522.uid.uidByte, mfrc522.uid.size);
        
      }
    }
    else
    {
      Serial.println(0);
    }
  }
}

byte RFID_CARD::string2ByteArray(char input[]) 
{
  // converting string to byte array
  int loop = 0;
  int i = 0;

  while (input[loop] != '\0') 
  {
    this->readBlockData[i++] = input[loop++];
  }
  return readBlockData;
}

String RFID_CARD::byteArray2string(byte input[])
{
  // converting string to byte array
  int loop = 0;
  int i = 0;
  char c;

  while (input[loop] != -1) 
  {
    c = input[loop++];
    this->data += c;
  }
  return this->data;
}

String RFID_CARD::decToHexa(int n) {
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

String RFID_CARD::WriteDataToBlock(int blockNum, byte blockData[]) 
{
  /* Authenticating the desired data block for write access using Key A */
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) 
  {
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } 
  else 
  {
    //Serial.println("Authentication success");
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
    return "200";
  }
}

String RFID_CARD::ReadDataFromBlock(int blockNum, byte readBlockData[]) 
{
  /* Authenticating the desired data block for Read access using Key A */
  byte status = this->mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) 
  {  
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } 
  else 
  {
    //Serial.println("Authentcation success");
  }

  /* Reading data from the Block */
  status = mfrc522.MIFARE_Read(blockNum, readBlockData, &bufferLen);
  if (status != MFRC522::STATUS_OK) 
  {
    //Serial.print("Reading failed: ");
    //Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } 
  else 
  {
    for (int j = 0; j < (this->bufferLen - 2); j++) {
      this->data += this->decToHexa(readBlockData[j]);
    }
    //Serial.println(this->data);
    return this->data;
  }
}