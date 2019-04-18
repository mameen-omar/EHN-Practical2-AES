/**
 * @file AES.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief AES encryption and decryption module header file. 
 * This file contains the function headers for the functions used for AES encryption and decryption.
 * Input must be ASCII and not hex. The functions implemented in this file, perform the AES encryption and decryption 
 * on a single block of size dictated by the variable AES_BLOCK_SIZE.
 * @version 0.1
 * @date 2019-03-20
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#ifndef AES_H
#define AES_H


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h> 

extern size_t VERBOSE; // for verbose output 
extern const size_t AES_BLOCK_SIZE; // number of blocks in BYTES 
extern const unsigned char invSBox[256]; // inverse s box
extern const unsigned char sbox[256]; // s box lookup table
extern const unsigned char Rcon[255]; // rcon lookup table

/**
 * @brief getNumRounds - Function to return the number of rounds of AES encryption and decryption based off of the
 * length of the key given in @param keyLength. 
 * 
 * @param keyLength - int - indicates the length of the key
 * @return int - the number of rounds based off of the length of the key passed in the parameter @param keyLength. 
 * If the length of the key is not valid, returns -1. 
 */
int getNumRounds(int);

/**
 * @brief AESEncrypt - Function to encrypt a single block of plaintext passed in as parameter @parameter plainText using AES encryption, 
 * for 128, 192 and 256 bit keys. Validates the keylength and returns the corresponding ciphertext. The caller of the function must ensure that the 
 * returned ciphertext pointer is freed. The ciphertext returned is always 16 bytes and the plainText must be 16 bytes or less. Makes use of zero padding.
 * All input must be in ASCII and NOT hex.  
 * @param char - unsigned char* plainText - pointer to the plaintext that needs to be encrypted using AES encryption. 
 * @param char - unsigned char* key - reference to the key that must be used for AES encryption. 
 * @param plainTextLength - length of the plaintext in @param plainText to be encrypted.  
 * @param keyLength - length of the key passed in as @param key used for the AES encryption. 
 * @return unsigned* char - Ciphertext resulting from the encryption of the plaintext passed in as @param plainText. 
 */
unsigned char* AESEncrypt(unsigned char*, unsigned char*, int, int); // plaintext, key , plaintext length, key length

/**
 * @brief AESDecrypt - Function to decrypt a single block of ciphertext passed in as parameter @parameter cipherText using AES decryption, 
 * for 128, 192 and 256 bit keys. Validates the keylength and returns the corresponding plaintext. The caller of the function must ensure that the 
 * returned plaintext pointer is freed. The plaintext returned is always 16 bytes and the plainText must be 16 bytes or less. Makes use of zero padding.
 * All input must be in ASCII and NOT hex.  
 * @param char - unsigned char* cipherText - pointer to the ciphertext that needs to be decrypted using AES decryption. 
 * @param char - unsigned char* key - reference to the key that must be used for AES decryption. 
 * @param cipherTextLength - length of the ciphertext in @param cipherText to be decrypted.  
 * @param keyLength - length of the key passed in as @param key used for the AES decryption. 
 * @return unsigned* char - Plaintext resulting from the decryption of the ciphertext passed in as @param cipherText. 
 */
unsigned char* AESDecrypt(unsigned char*, unsigned char*, int,int); // ciphertext, key, keyLength  

/**
 * @brief RijndaelKeySchedule - Function that performs the Rijndael key scheduling for AES encryption. Takes in the 
 * original key passed in as parameter @param originalKey and the length of the original key given as parameter. 
 * The caller must free the memory allocated and returned.
 * @param originalKey - unsigned char * - An unsigned char pointer to the original key. 
 * @param keyLength - int - length of originalKey passed in as a parameter @param originalKey
 * @return expandedKey - The key that has been expanded. 
 */
unsigned char* RijndaelKeySchedule(unsigned char*, int); // take in the original key and the key length (numBits)

/**
 * @brief printStateArray - Function to print the state array to the terminal in hex format.  
 * @param stateArray - the state array that should be printed to the terminal. 
 */
void printStateArray(uint8_t[4][4]);

/**
 * @brief getSBoxValue - Function to return the sBox value passed in as a parameter @param index. Requires the 
 * original value required in hex. 
 * 
 * @param index - unsigned char - hexadecimal representation of the index for which the SBox value is required. 
 * @return unsigned char - sBox value for the paramter @param index.
 */
unsigned char getSBoxValue(unsigned char);

/**
 * @brief getInvSBox - Function to return the inverse sBox value passed in as a parameter @param index. Requires the 
 * original value required in hex. 
 * 
 * @param index - unsigned char - hexadecimal representation of the index for which the inverse SBox value is required. 
 * @return unsigned char - inverse sBox value for the paramter @param index.
 */
unsigned char getInvSBox(unsigned char);

/**
 * @brief getRconValue - Function to return the Rcon value for the index passed in as a parameter @param num. Requires the 
 * original value required in hex. 
 * 
 * @param index - unsigned char - hexadecimal representation of the number for which the Rcon value is required during the key schedule. 
 * @return unsigned char - rCon value for the paramter @param num.
 */
unsigned char getRconValue(unsigned char);

/**
 * @brief SingleRotateLeft - Function to rotate the array passed in as a paramter @param word, a single time left (8 bits to the left), 
 * with the left most element becoming the right most element. As such: rotate(1d2c3a4f) = 2c3a4f1d.  
 * @param word - unsigned char *word - the array/word to be left rotated by 8 bits. 
 * @param wordLength  - int - length of the parameter @param word. 
 */
void SingleRotateLeft(unsigned char *, int);

/**
 * @brief KeyScheduleCore - Function that performs the key schedule core for the Rijndael Key Schedule.
 * Performs a single rotate left of the word passed in as @param word and applies the required s-box substituion and rcon XOR. 
 * @param char - unsigned char* word - pointer to the word onto which the key schedule core should be operated. 
 * @param wordLength  - length of the word passed in as a parameter @param word. 
 * @param rConIterationVal - the iteration value to be used for the rcon XOR. 
 */
void KeyScheduleCore(unsigned char*, int, int);

/**
 * @brief ShiftRows - Function to shift the state array according to the AES encryption standard for 128 - bits blocks
 * @param state - unsigned char -  is the current state of the ciphertext or plaintext during AES encryption or decryption 
 */
void ShiftRows(unsigned char[4][4], int);

/**
 *  @brief AddRoundKey - Function that performs the Bitwise XOR between state and key as per AES encryption.
 *  @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption 
 *  @param key - unsigned char - sub key to be added for the current round to the current state vector
 */
void AddRoundKey(unsigned char[4][4], unsigned char[4][4]); 

/**
 * @brief subBytes - Function that performs the sub byte operation where each value is replaced by the s box value
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption. 
 */
void subBytes(unsigned char[4][4]);

/**
 * @brief mixColumns - Function that performs the MixColumns step of AES as specified by AES encryption.  
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption  
 */
void mixColumns(unsigned char[4][4]);

/**
 * @brief invSubBytes - Function that performs the inverse of Function subBytes  
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption
 */
void invSubBytes(unsigned char[4][4]);

/**
 * @brief invShiftRows - Function to shift the state array Inverse according to the AES encryption standard for 128 - bits blocks 
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption 
 */
void invShiftRows(unsigned char[4][4], int);

/**
 * @brief SingleRotateRight - Function to rotate the array passed in as a paramter @param word, a single time right (8 bits to the right), 
 * with the right most element becoming the left most element. As such: rotate(1d2c3a4f) = 4f1d2c3a. 
 * 
 * @param word - unsigned char *word - the array/word to be right rotated by 8 bits. 
 * @param wordLength  - int - length of the parameter @param word. 
 */
void SingleRotateRight(unsigned char *, int);

/**
 * @brief getPaddedKeyLength - Function to return a valid key length (in bytes) based off of the current key length passed in 
 * as @param currentKeyLength. Corresponds to minimum and maximum key length required for AES encryption and decryption. 
 * The key will then be padded to the length of the value returned from this function. If the keylength is less than 16, will 
 * return 16. If greater than 16, but less than 24, will return 24. If greater than 32, will return -1. 
 * 
 * @param currentKeyLength - int - current key length in bytes, to be padded to the return value
 * @return int - the length in bytes that the key should be padded to. 
 */
int getPaddedKeyLength(int); 

/**
 * @brief invMixColumns - Function that does the inverse of the Mix Column Step for AES Encryption. Performs the gallois field multiplication
 * and the required XOR to the state passed in as a paramter @param state. 
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption. 
 */
void invMixColumns(unsigned char[4][4]); 

/**
 * @brief galloisFieldMult - Function to perform the Galois field multiplication operation required for the inverse mix columns and the 
 * mix columns operation of the AES encryption and decryption processes. Returns the result of the multiplication. 
 * @param a - first character to perform Galois field multiplication. 
 * @param b - second character to perform Galois field multiplication. 
 * @return unsigned char - Result of the Galois field multiplication. 
 */
unsigned char galloisFieldMult(unsigned char , unsigned char );

/**
 * @brief getRoundKey - Function to extract the correct sub-key to use for the appropriate round specified by @param
 * roundNum. Copies the sub-key from the expanded key in @param expandedKey to @param roundKey. 
 * @param char - expandedKey - The expanded key from which to extract the sub-key. 
 * @param char - roundKey - memory to which to copy the sub-key.
 * @param roundNum - int - the round number for which the sub-key is required. 
 */
void getRoundKey(unsigned char* , unsigned char* , int ); 

/**
 * @brief constructStateArray - Function to convert the state array from a flat 1D array to a multidimensional array. 
 * 
 * @param char flatArray -the 1D array to be converted. 
 * @param stateArray - the multidimensional array to which to copy the flat array elements to. 
 */
void constructStateArray(unsigned char*, unsigned char[][4]);

/**
 * @brief hexToInt -  Function that converts a given hex value into an integer. 
 * @param ch - hex value that wil be converted to int. 
 * @return uint8_t the converted int value. 
 */
uint8_t hexToInt(char c);

/**
 * @brief hexToAscii - Function that converts a given hex value to its ASCII equivalent.  
 * @param ch1 - char value of the first hex value.
 * @param ch2 - char value of the second hex value.
 */
uint8_t hexToAscii(char c, char d);

/**
 * @brief hexToAsciiString - Function that converts a given string of hex values into its ASCII equivalent.
 * A hex string contains hex chars and is "encoded" in ascii
 * In order to encrypt it, it must be converted to the equivalent ascii plain text string
 * plaintext string is half the size of hex, since two hex chars = 1 ascii char
 * if hex string is "4A" it will be converted to "J" in ascii which will have a hex representation of "4a"
 * The original hex string converted to hex staright or printed in hex straight rather will print or have the value "0x34", "0x31"
 * BASICALLY THE HEX STRING FF IS INTERPRETED AS THE CHARS FF, whereas when using this function we intend it to be "J", ie the char "J"
 * @param char* hexString - The string of hex values to be converted.
 * @param char* asciiString - The output of the converted hex string.
 * @param int hexStringLength - The length of parameter hexString.
 */
void hexToAsciiString(char* str, char* done,int);

/**
 * @brief Function name: asciiToHexString - convert an ascii String to an ascii string. 
 * @param asciiString - unsigned char* pointing to the ASCII String to be converted. 
 * @param hexString  - unsigned char* pointing to a memory where the converted Hex string should be stored. 
 * @param asciiStringLen - size_t containing the length of the ASCII String to be converted. 
 * @return unsigned char* asciiToHexString - pointer to the converted Hex String, pointing to the same memory location
 * as @param hexString. 
 */
unsigned char* asciiToHexString(unsigned char *asciiString, unsigned char* hexString, size_t asciiStringLen); 

/**
 * @brief validateNumRounds - Function that validates the number of rounds that have been passed in by the @param numRounds. Upon invalid validation,
 * relevent error information will be printed to terminal and the program will exit with an EXIT_FAILURE flag. 
 * @param numRounds - int - Integer value of the number rounds
 */
void validateNumRounds(int numRounds, int keyLength);

/**
 * @brief validatePlainTextLength - Function that validates the length of the plaintext. The validation is done against the AES_BLOCK_SIZE value
 * @param plainTextLength - int - The length of the plaintext text as an integer value 
 */ 
void validatePlainTextLength(size_t plainTextLength);

/**
 * @brief validateCipherTextLength - Function that validates the length of the ciphertext. The validation is done against the AES_BLOCK_SIZE value
 * @param cipherTextLength - int - The length of the cipher text as an integer value 
 */ 
void validateCipherTextLength(int cipherTextLength);

/**
 * @brief printAESBlock - Function to print a single block in hex format to the terminal.  
 * @param block - block to be printed. 
 */
void printAESBlock(unsigned char * temp);

/**
 * @brief Returns the last index of '/' in a given path, otherwise returns -1 if no '/' is found 
 * 
 * @param fileName The path to a file
 * @param fileNameLength The length of the provided file
 * @return int Index of the last '/' in the path, else -1 if no '/' was found
 */
int fileNameDirIndex(char* fileName, int fileNameLength);

/**
 * @brief stripDirectory - Function that removes path from the provided path to a file and returns only the file name
 * 
 * @param fileName The path to a specified file
 * @param extractedFileName The name of the file within the provided path to a file
 * @param extractedFilePath The path to file, excluding the file name
 * @param fileNameLength The length of the paramter @param fileName
 * @param slashIndex The index of the last '/' in the original file path passed in as a paramter @param fileName
 */
void stripDirectory(char * fileName, char* extractedFileName, char* extractedFilePath, int fileNameLength, int slashIndex);

/**
 * @brief Get the output file name from all the parameters passed in
 * @param type 0 - Encrypt, 1 - Decrypt
 * @param fileName The name of the input file
 * @param outputFileName The name of the output file
 * @param mode Chipher mode to be used (ECB, CBC, CFB)
 */
void getOutputFileName(int type, char* fileName, char* outputFileName, char*); 

/**
 * @brief isFileTxt - Function to determine if the file passed in as a paramter @param filename is a text file with extension
 * .txt or not. Returns a 1 if it is and a 0 if it isn't. 
 * 
 * @param fileName - unsigned char* fileName - path to file to determine if the file is a text file or not. 
 * @return uint8_t  - boolean indicating if it is a text file or not. (0 is not a text file, 1 is a text file)
 */
uint8_t isFileTxt(unsigned char * fileName); 


/**
 * @brief keyHexToAscii - Function to convert a key from a Hex string passed in as a paramter @param
 * hexKey to an ascii string. User must free the returned pointer to memory allocated. 
 * Returns the Ascii equivalent. The caller must free the pointer returned. 
 * @param char - unsigned char* hexKey - hex representation of the key to be converted to ASCII. 
 * @param keyLength - length of the hex representation of the key passed in as paramter @param hexKey. 
 * @return unsigned* - the ASCII representation of the hex key passed in as parameter @param hexKey. 
 */
unsigned char* keyHexToAscii(unsigned char* hexKey, int keyLength);


/**
 * @brief IVHexToAscii - Function to convert a initialization vector from a Hex string passed in as a paramter @param
 * hexIV to an ascii string. User must free the returned pointer to memory allocated. 
 * Returns the Ascii equivalent. The caller must free the pointer returned. 
 * @param char - unsigned char* hexIV - hex representation 
 * @param IVLength - length of the hex representation of the IV passed in as paramter @param hexIV. 
 * @return unsigned* - the ASCII representation of the hex IV passed in as parameter @param hexIV. 
 */
unsigned char* IVHexToAscii(unsigned char* hexIV, int IVLength); 

/**
 * @brief XORBlocks - Function to XOR two blocks of length @param length and retuns the XOR'd result.
 * User must free the memory returned. 
 * @param char - block1 - First block to be XOR'd. 
 * @param char - block2 - Second block to be XOR'd. 
 * @param length - length of the blocks to be XOR'd. 
 * @return unsigned* - Result of the XOR.  
 */
unsigned char* XORBlocks(unsigned char* block1, unsigned char* block2, int length);
#endif
