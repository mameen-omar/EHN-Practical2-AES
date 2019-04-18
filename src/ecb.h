#ifndef ECB_H
#define ECB_H
/**
 * @file ecb.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Electronic code book (ECB) - AES header file
 * This file contains the function headers of the functions used for the ECB mode of AES encryption. 
 * This system supports both file and user input encryption, as hex or ascii input. 
 * If the user inputs data to be encrypted or decrypted, the result will be printed to the terminal, whereas 
 * if the user specifies a file to be encrypted or decrypted, a new file will be created and the result will be written
 * to the file. 
 * The ECB Encryption platform encrypts and decrypts blocks 16 bytes at a time, using 0 padding. 
 * @version 0.1
 * @date 2019-04-17
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "AES.h"
#include "stdio.h"
#include "math.h"

/**
 * @brief ecbEncrypt - Function to encrypt the user input pointed to by @param plainText and print encrypted 
 * result in hex to terminal. Performs encryption using the ECB mode prints the result to the terminal for each block in hex.
 * If any input is hex, it will convert it to ascii, perform encryption and print it in hex. Makes use of zero padding. 
 * @param char - unsigned char* plainText - the user input to be encrypted. 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param plainTextLength - int - the length of the plaintext to be encrypted in @param plainText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 */
void ecbEncrypt(unsigned char* plainText, unsigned char* key,
                int plainTextLength, int keyLength, int isTextHex, int isKeyHex); 

/**
 * @brief ecbDecrypt - Function to decrypt the user input pointed to by @param cipherText and print decrypted 
 * result in hex to terminal. Performs decryption using the ECB mode prints the result to the terminal for each block in hex. 
 * If any input is hex, it will convert it to ascii, perform decryption and print it in hex. Makes use of zero padding. 
 * @param char - unsigned char* cipherText - the user input to be decrypted. 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param cipherTextLength - int - the length of the ciphertext to be encrypted in @param cipherText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 */
void ecbDecrypt(unsigned char* cipherText, unsigned char* key,
                int cipherTextLength, int keyLength, int isTextHex, int isKeyHex); 

/**
 * @brief ecbEcryptHelper - Helper function used to encrypt the plaintext pointed to by @param plainText using ECB mode of encryption 
 * and output the result to the terminal. Encrypts a single block of 16 bytes using AES encryption.
 * @param char - unsigned char* plainText - the block input to be encrypted. 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param plainTextLength - int - the length of the plaintext to be encrypted in @param plainText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 */
void ecbEcryptHelper(unsigned char* plainText, unsigned char* key, int plainTextLength,int keyLength);

/**
 * @brief ecbDecryptHelper - Helper function used to decrypt the ciphertext pointed to by @param cipherText using ECB mode of decryption 
 * and output the result to the terminal. Decrypts a single block of 16 bytes using AES decryption.
 * @param char - unsigned char* cipherText - the block input to be encrypted. 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param cipherTextLength - int - the length of the ciphertext to be encrypted in @param cipherText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 */
void ecbDecryptHelper(unsigned char* cipherText, unsigned char* key, int cipherTextLength,int keyLength);

/**
 * @brief ecbEncryptFile - Function to encrypt the file with name @param fileName and write the encrypted 
 * version to file with ecbEncrypted appended to the original filename. Performs encryption using the ecb mode and 
 * writes the result to a file. If any input is hex, it will convert it to ascii, perform encryption and write it back as ASCII. All terminal output, 
 * however, will be hex. Makes use of zero padding.
 * @param char - unsigned char* fileName - the path to the file to be encrypted. 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 */
void ecbEncryptFile(unsigned char* fileName, unsigned char* key, int keyLength, int isTextHex, int isKeyHex); 

/**
 * @brief ecbDecryptFile - Function to encrypt the file with name @param fileName and write the decrypted 
 * version to file with ecbDecrypted appended to the original filename. Performs decryption using the ecb mode and 
 * writes the result to a file. If any input is hex, it will convert it to ascii, perform encryption and write it back as ASCII. All terminal output, 
 * however, will be hex. Makes use of zero padding.
 * @param char - unsigned char* fileName - the path to the file to be decrypted. 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 */
void ecbDecryptFile(unsigned char* fileName, unsigned char* key, int keyLength, int isTextHex, int isKeyHex); 

#endif // MACRO
