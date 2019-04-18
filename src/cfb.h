/**
 * @file cfb.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Cipher Feedback (CFB) - AES header file
 * This file contains the function headers of the functions used for the CFB mode of AES encryption. 
 * This system supports both file and user input encryption, as hex or ascii input. 
 * If the user inputs data to be encrypted or decrypted, the result will be printed to the terminal, whereas 
 * if the user specifies a file to be encrypted or decrypted, a new file will be created and the result will be written
 * to the file. 
 * The CFB Encryption platform encrypts and decrypts blocks 16 bytes at a time, using 0 padding. 
 * @version 0.1
 * @date 2019-03-28
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#ifndef CFB_H
#define CFB_H

#include "AES.h"

/**
 * @brief Variable - VERBOSE - specifies if verbose output should be printed or not
 * 
 */
extern size_t VERBOSE; 
/**
 * @brief Variable - AES_BLOCK_SIZE - specifies the length per AES block - 16 bytes
 * 
 */
extern const size_t AES_BLOCK_SIZE;
/**
 * @brief Variable - size_t const shiftRegLength - used to specify the length of the shift register.
 */
extern const size_t shiftRegLength; 
/**
 * @brief Variable - size_t const streamSize - used to speciffy the length of the stream per encryption round.
 */
extern const size_t streamSize; 

/**
 * @brief cfbEncryptFile - Function to encrypt the file with name @param fileName and write the encrypted 
 * version to file with cfbEncrypted appended to the original filename. Performs encryption using the cfb mode and 
 * writes the result to a file. If any input is hex, it will convert it to ascii, perform encryption and write it back as ASCII. All terminal output, 
 * however, will be hex. Makes use of zero padding.
 * @param char - unsigned char* fileName - the path to the file to be encrypted 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cfb encryption
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */
void cfbEncryptFile(unsigned char* fileName, unsigned char* key, unsigned char* initializationVector, 
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex); 


/**
 * @brief cfbDecryptFile - Function to decrypt the file with name @param fileName and write the decrypted 
 * version to file with cfbDecrypted appended to the original filename. Performs decryption using the cfb mode and 
 * writes the result to a file. If any input is hex, it will convert it to ascii, perform decryption and write it back to the file in the same format as the input. 
 * That is if the input file was a hexString, the decrypted file will also contain a hex string. All terminal output, 
 * however, will be hex. Makes use of zero padding.
 * @param char - unsigned char* fileName - the path to the file to be decrypted 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cfb decryption
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */                    
void cfbDecryptFile(unsigned char* fileName, unsigned char* key, unsigned char* initializationVector, 
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex); 


/**
 * @brief cfbEncrypt - Function to encrypt the user input pointed to by @param plainText and print encrypted 
 * result in hex to terminal. Performs encryption using the cfb mode prints the result to the terminal for each block in hex. 
 * If any input is hex, it will convert it to ascii, perform encryption and print it in hex. Makes use of zero padding. 
 * @param char - unsigned char* plainText - the user input to be encrypted. 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cfb encryption
 * @param plainTextLength - - int - the length of the plaintext to be encrypted in @param plainText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */
void cfbEncrypt(unsigned char* plainText, unsigned char* key, unsigned char* initializationVector, 
                int plainTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex); 


/**
 * @brief cfbDecrypt - Function to decrypt the user input pointed to by @param cipherText and print decrypted 
 * result in hex to terminal. Performs decryption using the cfb mode prints the result to the terminal for each block in hex. 
 * If any input is hex, it will convert it to ascii, perform decryption and print it in hex. Makes use of zero padding. 
 * @param char - unsigned char* cipherText - the user input to be decrypted. 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param char - unsigned char* initializationVector - the initialization vector to use for cfb decryption. 
 * @param cipherTextLength - int - the length of the ciphertext to be encrypted in @param cipherText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 * @param initializationVectorLength - int - the length of the key specified in @param initializationVector.
 * @param isTextHex - int - boolean used to signify whether the file pointed to by @param fileName is a hexString or ASCII string. (1 = file is a hexString)
 * @param isKeyHex - int - boolean used to signify whether the key pointed to by @param key is a hexString or ASCII string. (1 = file is a hexString)
 * @param isIvHex - int - boolean used to signify whether the IV pointed to by @param initializationVector is a hexString or ASCII string. (1 = file is a hexString)
 */
void cfbDecrypt(unsigned char* cipherText, unsigned char* key, unsigned char* initializationVector, 
                int cipherTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex); 


#endif
