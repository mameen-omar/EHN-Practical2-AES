// EHN 410 - Mohamed Ameen Omar - u16055323 - 2019

/**
 * @file cfbTester.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief  Main file. 
 * @version 0.1
 * @date 2019-03-19
 * 
 * @copyright Copyright (c) 2019
 * 
 */

// Vulgrind: 
//  valgrind -v --leak-check=yes ./main

#include "cfb.h"



int main(int argc, char * argv[])
{
    // char* fileName = "./testFiles/sourceEnc";
    // char* fileNameD = "./testFiles/cfbEncrypted_sourceEnc";
    // unsigned char* key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"; //"2b7e151628aed2a6abf7158809cf4f3c";
    // unsigned char* IV = "4c6a606a90bd84c0402ee2a81783d6e"; //"000102030405060708090a0b0c0d0e0f"; 
    // unsigned char* plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    // unsigned char* cipherText = "Hello";
    // cfbEncryptFile(fileName, key,IV,strlen(key),strlen(IV),0,1,1); // all hex
    // cfbDecryptFile(fileNameD, key,IV,strlen(key),strlen(IV),0,1,1);
    // cfbEncrypt(plaintext,key,IV, strlen(plaintext), strlen(key), strlen(IV), 0,1,1);
    // cfbDecrypt(cipherText,key,IV, strlen(cipherText), strlen(key), strlen(IV), 0,1,1);

    unsigned char* fileName = "./testFiles/openHelloEnc.png"; 
    unsigned char* key = "30B568D4B12175C14203C19A20B77968"; 
    unsigned char* IV = "D90107C92561219775C92E8A66F6BA19"; 

    cfbDecryptFile(fileName, key,IV,strlen(key),strlen(IV),0,1,1);
    return 0;
}
