// EHN 410 - Mohamed Ameen Omar - u16055323 - 2019

/**
 * @file cbcTester.c
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

#include "cbc.h"

// FILES WORK IF WE WRITE THE NULL CHARS 
// In terms of encryption and decryption

int main(int argc, char * argv[])
{
    // printf("CBC TESTER\n");
    // char* fileName = "./testFiles/hello.txt";
    // char* fileNameD = "./testFiles/cbcEncrypted_hello.txt";

    // unsigned char* key128 = "2b7e151628aed2a6abf7158809cf4f3c"; 
    // size_t keyLength = strlen(key128); // 16 byte key, 32 since hex

    // unsigned char* IV = "AES_encrypt"; 
    // int IVLength = 16;
    // unsigned char* tempKey = "AES_encrypt"; 

    // //cbcEncryptFile()
    // cbcEncryptFile(fileName, tempKey,IV,keyLength,IVLength,0,0,0); // all hex
    // cbcDecryptFile(fileNameD, tempKey,IV,keyLength,IVLength,0,0,0);
   
    // unsigned char* key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    char* fileName = "./testFiles/hello.txt";
    char* fileNameD = "./testFiles/cbcEncrypted_hello.txt";
    unsigned char* cipherFileName = ""; 
    unsigned char* key = "2b7e151628aed2a6abf7158809cf4f3c";
    unsigned char* IV = "000102030405060708090a0b0c0d0e0f"; 


    cbcEncryptFile(fileName, key,IV,strlen(key),strlen(IV),1,1,1); // all hex
    cbcDecryptFile(fileNameD, key,IV,strlen(key),strlen(IV),1,1,1);

    // unsigned char* key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 ";
    // cbcEncryptFile(fileName, key256,IV,strlen(key256),IVLength,1,1,1); // all hex
    // cbcDecryptFile(fileNameD, key256,IV,strlen(key256),IVLength,1,1,1);

    // unsigned char* plaintextHex = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    // unsigned char* key = "2b7e151628aed2a6abf7158809cf4f3c";
    // unsigned char* IV = "000102030405060708090a0b0c0d0e0f"; 

    // cbcEncrypt(plaintextHex,key,IV,strlen(plaintextHex),strlen(key),strlen(IV), 1,1,1);
    
    return 0;
}
