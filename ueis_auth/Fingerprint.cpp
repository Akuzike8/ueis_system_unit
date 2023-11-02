#include "Fingerprint.h"
#include <Adafruit_Fingerprint.h>

namespace fingerprint
{
  void init(Adafruit_Fingerprint finger) 
  {
    if (finger.verifyPassword()) {}
    else 
    {
      Serial.println("Did not find fingerprint sensor :(");
      while (1) { delay(1); }
    }

    finger.getParameters();
  }

  void capture(Adafruit_Fingerprint finger,int p)
  {
    while (p != FINGERPRINT_OK) 
    {
      p = finger.getImage();
      switch (p) 
      {
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
    switch (p) 
    {
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

  void enroll(Adafruit_Fingerprint finger)
  {
      int id = 0;
      id = getId();
      int p = -1;

      // capturing fingerprint
      capture(finger,p);
      
      Serial.println(3);
      delay(1000);
      p = 0;
      while (p != FINGERPRINT_NOFINGER) {
        p = finger.getImage();
      }

      p = -1;
      Serial.println("Place same finger again");
      delay(50);

      // capturing fingerprint
      capture(finger,p);

      // creating a fingerprint data model
      p = finger.createModel();

      //if (p == FINGERPRINT_OK) {}
     // else{Serial.println(4);} 

      // storing fingerprint
      p = finger.storeModel(id);
      if (p == FINGERPRINT_OK) {Serial.println(1);}
      else{Serial.println(2);}

             
      
  }

  void verify(Adafruit_Fingerprint finger)
  {
    int p = -1;
    int fid = 0;

    // capturing fingerprint
    capture(finger,p);

    // authenticating fingerprint
    p = finger.fingerSearch();
    fid = finger.fingerID;
    Serial.println(fid);

  }

  int getId()
  {
    int id = 0;
    boolean end = false;

    while(true)
    {
      if(end == true)
      {
        break;
      }

      while(Serial.available() > 0)
      {
        id = Serial.read();
        id = id - 48;
        if (id != 0) 
        {
          end = true;
          break;
        }
      }
    }

    return id;
  }
}