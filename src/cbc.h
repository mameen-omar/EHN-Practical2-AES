// Mohamed Ameen Omar (u16055323)

/**
 * @file cbc.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Cipher Block Chaining (CBC) - AES Header file
 * This file contains the function headers of the functions used for the CBC mode of AES encryption. 
 * This system supports both file and user input encryption, as hex or ascii input. 
 * If the user inputs data to be encrypted or decrypted, the result will be printed to the terminal, whereas 
 * if the user specifies a file to be encrypted or decrypted, a new file will be created and the result will be written
 * to the file. 
 * The CBC Encryption platform encrypts and decrypts blocks 16 bytes at a time, using 0 padding. 
 * The IV is limited to 16 bytes and the key is limited to 32 bytes as per the AES encryption standard
 * @version 0.1
 * @date 2019-03-28
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#ifndef CBC_H
#define CBC_H

#include "AES.h"
#include <stdio.h>
#include <string.h>

extern size_t VERBOSE; 
extern const size_t AES_BLOCK_SIZE; // 16 is the block size for AES (from AES.h)

/**
 * @brief cbcEncryptFile - Function to encrypt the file with name @param fileName and write the encrypted 
 * version to file with cbcEncrypted appended to the original filename. Performs encryption using the cbc mode and 
 * writes the result to a file. If any input is hex, it will convert it to ascii, perform encryption and write it back as ASCII. All terminal output, 
 * however, will be hex. Makes use of zero padding.
 * @param char - unsigned char* fileName - the path to the file to be encrypted 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cbc encryption
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */
void cbcEncryptFile(unsigned char* fileName, unsigned char* key, unsigned char* initializationVector, 
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex); 

/**
 * @brief cbcDecryptFile - Function to decrypt the file with name @param fileName and write the decrypted 
 * version to file with cbcDecrypted appended to the original filename. Performs decryption using the cbc mode and 
 * writes the result to a file. If any input is hex, it will convert it to ascii, perform decryption and write it back to the file in the same format as the input. 
 * That is if the input file was a hexString, the decrypted file will also contain a hex string. All terminal output, 
 * however, will be hex. Makes use of zero padding.
 * @param char - unsigned char* fileName - the path to the file to be decrypted 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cbc decryption
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */             
void cbcDecryptFile(unsigned char* fileName, unsigned char* key, unsigned char* initializationVector, 
                   int keyLength, int initializationVectorLength,int isTextHex, int isKeyHex, int isIvHex); 


/**
 * @brief cbcEncrypt - Function to encrypt the user input pointed to by @param plainText and print encrypted 
 * result in hex to terminal. Performs encryption using the cbc mode prints the result to the terminal for each block in hex. 
 * If any input is hex, it will convert it to ascii, perform encryption and print it in hex. Makes use of zero padding. 
 * @param char - unsigned char* plainText - the user input to be encrypted. 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cbc encryption
 * @param plainTextLength - - int - the length of the plaintext to be encrypted in @param plainText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */
void cbcEncrypt(unsigned char* plainText, unsigned char* key, unsigned char* initializationVector, 
                    int plainTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex);

/**
 * @brief cbcDecrypt - Function to decrypt the user input pointed to by @param cipherText and print decrypted 
 * result in hex to terminal. Performs decryption using the cbc mode prints the result to the terminal for each block in hex. 
 * If any input is hex, it will convert it to ascii, perform decryption and print it in hex. Makes use of zero padding. 
 * @param char - unsigned char* cipherText - the user input to be decrypted. 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cbc decryption. 
 * @param cipherTextLength - int - the length of the ciphertext to be encrypted in @param cipherText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */
void cbcDecrypt(unsigned char* cipherText, unsigned char* key, unsigned char* initializationVector, 
                    int cipherTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex); 
#endif
