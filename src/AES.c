/**
 * @file AES.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief AES encryption and decryption module implementation file. 
 * This file contains the implementation of the functions used for AES encryption and decryption.
 * Input must be ASCII and not hex. The functions implemented in this file, perform the AES encryption and decryption 
 * on a single block of size dictated by the variable AES_BLOCK_SIZE.  
 * @version 0.1
 * @date 2019-03-20
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#include "AES.h"

/**
 * @brief Variable- const size_t AES_BLOCK_SIZE. 
 * Used to dictate the length in bytes of a single AES block used for encryption and decryption. 
 * Set to 16 bytes for a single block
 */
const size_t AES_BLOCK_SIZE = 16; // 16 is the block size for AES

/**
 * @brief Variable- size_t VERBOSE 
 * Used to dictate whether verbose output is printed to the terminal or not. 
 * If 0, does not print verbose. If 1, prints verbose. 
 */
size_t VERBOSE = 0; 

/**
 * @brief const unsigned char sbox. 
 * Lookup table for the sbox values used during AES Encryption.  
 */
const unsigned char sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,     //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,     //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,     //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,     //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,     //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,     //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,     //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,     //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,     //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,     //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,     //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,     //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,     //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,     //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,     //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };   //F

/**
 * @brief const unsigned char invSBox.  
 * Lookup table for the inverse sbox values used during AES Decryption.  
 */    
const unsigned char invSBox[256] = { 
    /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f  */
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb, /*0*/
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb, /*1*/
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e, /*2*/
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25, /*3*/
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92, /*4*/
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84, /*5*/
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06, /*6*/
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b, /*7*/
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73, /*8*/
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e, /*9*/
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b, /*a*/
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4, /*b*/
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f, /*c*/
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef, /*d*/
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61, /*e*/
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d  /*f*/ };

/**
 * @brief const unsigned char Rcon.  
 * Lookup table for the Rcon values used during Rijndael Key Schedule during the AES Encryption and Decryption.  
 */    
const unsigned char Rcon[255] = { 
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };


/**
 * @brief getNumRounds - Function to return the number of rounds of AES encryption and decryption based off of the
 * length of the key given in @param keyLength. 
 * 
 * @param keyLength - int - indicates the length of the key
 * @return int - the number of rounds based off of the length of the key passed in the parameter @param keyLength. 
 * If the length of the key is not valid, returns -1. 
 */
int getNumRounds(int keyLength)
{
    if(keyLength == 16) {
        return 10;
    } else if (keyLength == 24) {
        return 12; 
    } else if (keyLength == 32) {
        return 14;
    } else {
        return -1;
    }      
}

/**
 * @brief getSBoxValue - Function to return the sBox value passed in as a parameter @param index. Requires the 
 * original value required in hex. 
 * 
 * @param index - unsigned char - hexadecimal representation of the index for which the SBox value is required. 
 * @return unsigned char - sBox value for the paramter @param index.
 */
unsigned char getSBoxValue(unsigned char index)
{
    return sbox[index];
}

/**
 * @brief getInvSBox - Function to return the inverse sBox value passed in as a parameter @param index. Requires the 
 * original value required in hex. 
 * 
 * @param index - unsigned char - hexadecimal representation of the index for which the inverse SBox value is required. 
 * @return unsigned char - inverse sBox value for the paramter @param index.
 */
unsigned char getInvSBox(unsigned char index)
{
    return invSBox[index];
}

/**
 * @brief getRconValue - Function to return the Rcon value for the index passed in as a parameter @param num. Requires the 
 * original value required in hex. 
 * 
 * @param index - unsigned char - hexadecimal representation of the number for which the Rcon value is required during the key schedule. 
 * @return unsigned char - rCon value for the paramter @param num.
 */
unsigned char getRconValue(unsigned char num)
{
    return Rcon[num];
}

/**
 * @brief getPaddedKeyLength - Function to return a valid key length (in bytes) based off of the current key length passed in 
 * as @param currentKeyLength. Corresponds to minimum and maximum key length required for AES encryption and decryption. 
 * The key will then be padded to the length of the value returned from this function. If the keylength is less than 16, will 
 * return 16. If greater than 16, but less than 24, will return 24. If greater than 32, will return -1. 
 * 
 * @param currentKeyLength - int - current key length in bytes, to be padded to the return value
 * @return int - the length in bytes that the key should be padded to. 
 */
int getPaddedKeyLength(int currentKeyLength)
{
    if(currentKeyLength <= 16)
        return 16; 
    
    if(currentKeyLength <= 24)
        return 24;
    
    if(currentKeyLength <=32)
        return 32;

    return -1;
}


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
unsigned char* AESEncrypt(unsigned char* plainText, unsigned char* key, int plainTextLength,int keyLength)
{

    if(VERBOSE == 1) {  
        printf("\n****************************************************************************************************************\n");
        printf("Beginning AES Encryption on a single block\n");
    }
    
    keyLength = getPaddedKeyLength(keyLength);

    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);

    validateNumRounds(numRounds, keyLength);
    // end check key length 

    //check plaintext length, if greater than 16 - cant be done
    // if less than 128 bits so 128/8 chars add zero padding
    validatePlainTextLength(plainTextLength);

    unsigned char* paddedKey = calloc((keyLength), sizeof(unsigned char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,key,keyLength);  

    // Copy to padded, memcpy will pad an ASCII 0 for every char missing (Null char) 
    // maximum number of char is 16 since 1 char = 1 byte and 128 bits = 16 bytes
    unsigned char* paddedPlainText = calloc((AES_BLOCK_SIZE), sizeof(char));
    memcpy(paddedPlainText,plainText,AES_BLOCK_SIZE);  
    plainTextLength = AES_BLOCK_SIZE; // length of plainText is now 16 with/without zero padding

    if(VERBOSE == 1) {
        printf("Padded plaintext in hexadecimal format is:\n"); 
        for(int x = 0; x < AES_BLOCK_SIZE;x++) {
            printf("%02X\t", paddedPlainText[x]);
        }
        printf("\n");
        printf("Padded Key length is: %d bytes.\n", keyLength);
        printf("Number of rounds of encryption: %d rounds. \n", numRounds);
        printf("Padded Key in hexadecimal format is:\n");
        for(int x = 0; x<keyLength;x++) {
            if(x%AES_BLOCK_SIZE == 0 && x != 0){
                printf("\n");
            }
            printf("%02X\t", paddedKey[x]);
        }
        printf("\n");        
    }
    
    // construct state array
    uint8_t stateArray[4][4]; 
    constructStateArray(paddedPlainText,stateArray);
    if(VERBOSE == 1) {
        printf("Initial State Array is:\n");
        printStateArray(stateArray);
    }
    
    // key schedule, get expanded keys
    unsigned char* expandedKey = RijndaelKeySchedule(paddedKey, keyLength); // (numRounds+1) * 16 length key in bytes 

    if(VERBOSE == 1) {
        printf("Expanded Key is:\n");
        for(int x =0; x<(numRounds+1)*16; x++) {
            if(x % 16 == 0 && x != 0)
                printf("\n");
            printf("%02X\t", expandedKey[x]);
        }
        printf("\n");
    }

    unsigned char keyBlock[4][4];

    /* Actual Encryption Start */
    // initial 
    // all operations done on the stateArray directly
    unsigned char* tempKey = calloc(AES_BLOCK_SIZE, sizeof(char));

    getRoundKey(expandedKey,tempKey,0); // first round key used
    constructStateArray(tempKey,keyBlock);   
    AddRoundKey(stateArray,keyBlock);  

    if(VERBOSE == 1) {
        printf("Begin Round 0\n");
        printf("Round key for round %d is:\n", 0);
        printStateArray(keyBlock);
        printf("Added Round Key.\n");
        printf("State Array after add round key:\n");
        printStateArray(stateArray);
        printf("End of Round 0\n");
    }     
   
    //all other rounds
    uint8_t rcounter;
    for(rcounter = 0; rcounter < numRounds-1; rcounter++) {
        if(VERBOSE == 1) {
            printf("Round %d begin\n", rcounter+1);
            printf("Computing Sub Bytes\n");
        }
        subBytes(stateArray);
        if(VERBOSE == 1) {
            printf("State array after sub bytes\n");
            printStateArray(stateArray);
            printf("Computing Shift Rows\n");
        }

        ShiftRows(stateArray,AES_BLOCK_SIZE);      
        if(VERBOSE == 1) { 
            printf("State array after Shift Rows\n");
            printStateArray(stateArray);
            printf("Computing Mix columns\n");
        }

        mixColumns(stateArray);
        if(VERBOSE == 1) { 
            printf("State array after Mix columns\n");
            printStateArray(stateArray);
        }

        // add round key
        getRoundKey(expandedKey,tempKey,rcounter+1);
        constructStateArray(tempKey,keyBlock);
        
        AddRoundKey(stateArray,keyBlock);
        if(VERBOSE == 1) { 
            printf("Round key for round %d\n", rcounter+1);
            printStateArray(keyBlock);
            printf("Computing add round key\n");
            printf("State array after Add round key\n");
            printStateArray(stateArray);
            printf("End of Round %d\n", rcounter +1);
        }   
    }
    // last round

    if(VERBOSE == 1) {
        printf("Begin round %d\n", rcounter+1);
        printf("Computing Sub Bytes\n");
    }

    // sub bytes
    subBytes(stateArray);

    if(VERBOSE == 1) {
            printf("State array after sub bytes\n");
            printStateArray(stateArray);
            printf("Computing Shift Rows\n");
    }
    // shift rows
    ShiftRows(stateArray,AES_BLOCK_SIZE);
    if(VERBOSE == 1) { 
        printf("State array after Shift Rows\n");
        printStateArray(stateArray);
    }
    // add round key
    getRoundKey(expandedKey,tempKey,rcounter+1);
    constructStateArray(tempKey,keyBlock); // flat to state
    AddRoundKey(stateArray,keyBlock);
    if(VERBOSE == 1) { 
            printf("Round key for round %d\n", rcounter+1);
            printStateArray(keyBlock);
            printf("Computing add round key\n");
            printf("State array after Add round key\n");
            printStateArray(stateArray);
            printf("End of Round %d\n", rcounter +1);
    }

    // free all heap allocated memory 
    free(paddedPlainText);
    free(expandedKey);
    free(tempKey);
    free(paddedKey);

     // return cipher text 
    unsigned char* cipherText = calloc(AES_BLOCK_SIZE, sizeof(char));
    int counter = 0;
    for(int col = 0; col <4; col++) {
        for(int row = 0; row < 4; row++){
            cipherText[counter] = stateArray[row][col];
            counter++;
        }
    }
    
    if(VERBOSE == 1) {
        printf("\nResulting CipherText in Hexadecimal format is:\n");
        printAESBlock(cipherText);
        printf("End of AES encryption\n");
        printf("****************************************************************************************************************\n\n");
    } 
    return cipherText;
}

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
unsigned char * AESDecrypt(unsigned char* cipherText, unsigned char* key, int cipherTextLength, int keyLength)
{
    if(VERBOSE == 1) { 
        printf("\n****************************************************************************************************************\n");
        printf("Beginning AES Decryption on a single block\n");
    }

    keyLength = getPaddedKeyLength(keyLength);
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds, keyLength);
    // end check key length 

    //check cipherText length
    // if less than 128 bits so 128/8 chars add zero padding
    validateCipherTextLength(cipherTextLength);

    unsigned char* paddedKey = calloc((keyLength),sizeof(char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,key,keyLength);  

    // Copy to padded, memcpy will pad an ASCII 0 for every char missing (Null char) 
    // maximum number of char is 16 since 1 char = 1 byte and 128 bits = 16 bytes
    unsigned char* paddedCipherText = calloc((AES_BLOCK_SIZE), sizeof(char));
    memcpy(paddedCipherText,cipherText,AES_BLOCK_SIZE);  
    cipherTextLength = AES_BLOCK_SIZE; // length of plainText is now 16 with/without zero padding

    if(VERBOSE == 1) {
        printf("Padded CipherText in hexadecimal format is:\n"); 
        for(int x = 0; x < AES_BLOCK_SIZE;x++) {
            printf("%02X\t", paddedCipherText[x]);
        }
        printf("\n");
        printf("Padded Key length is: %d bytes.\n", keyLength);
        printf("Number of rounds of encryption: %d rounds. \n", numRounds);
        printf("Padded Key in hexadecimal format is:\n");
        for(int x = 0; x<keyLength;x++) {
            if(x%AES_BLOCK_SIZE == 0 && x != 0){
                printf("\n");
            }
            printf("%02X\t", paddedKey[x]);
        }
        printf("\n");        
    }
    // construct state array
    uint8_t stateArray[4][4];
    constructStateArray(paddedCipherText,stateArray);
    if(VERBOSE == 1) { 
        printf("Initial State Array is:\n");
        printStateArray(stateArray);
    }
    /* Actual Decryption Start */
    // key schedule, get expanded keys
    unsigned char* expandedKey = RijndaelKeySchedule(paddedKey, keyLength); // (numRounds+1) * 16 length key in bytes  
    if(VERBOSE == 1) {
        printf("Expanded Key is:\n");
        for(int x =0; x<(numRounds+1)*16; x++) {
            if(x%16 == 0 && x != 0)
                printf("\n");
            printf("%02X\t", expandedKey[x]);
        }
        printf("\n");
    }
    unsigned char keyBlock[4][4];
    
    unsigned char* tempKey = calloc(AES_BLOCK_SIZE,sizeof(char));
    
    // initial 
    // all operations done on the stateArray directly
    getRoundKey(expandedKey,tempKey,numRounds); // last round key used
    constructStateArray(tempKey,keyBlock);
    
    AddRoundKey(stateArray,keyBlock);
    if(VERBOSE == 1) {
        printf("Begin Round 0\n");
        printf("Round key for round %d is:\n", 0);
        printStateArray(keyBlock);
        printf("Added Round Key.\n");
        printf("State Array after add round key:\n");
        printStateArray(stateArray);
        printf("Computing Inverse Shift Rows\n");
    } 
    invShiftRows(stateArray,AES_BLOCK_SIZE);
    if(VERBOSE == 1) {
        printf("State Array after Inverse Shift Rows:\n");
        printStateArray(stateArray);
        printf("Computing Inverse Sub bytes\n");
    }
    invSubBytes(stateArray);
    if(VERBOSE == 1) {
        printf("State Array after Inverse Sub bytes:\n");
        printStateArray(stateArray);
        printf("End of Round 0");
    }

    //all other rounds
    uint8_t rcounter;
    for(rcounter = 0; rcounter < numRounds-1; rcounter++)
    {

        getRoundKey(expandedKey,tempKey,numRounds - rcounter-1);
        constructStateArray(tempKey,keyBlock);
        AddRoundKey(stateArray,keyBlock); 
        if(VERBOSE == 1) { 
            printf("Begin of Round %d\n", rcounter +1);
            printf("Round key for round %d\n", rcounter+1);
            printStateArray(keyBlock);
            printf("Computing add round key\n");
            printf("State array after Add round key\n");
            printStateArray(stateArray);  
            printf("Computing Inverse Mix Columns\n");        
        }

        invMixColumns(stateArray);        
        if(VERBOSE == 1) { 
            printf("State array after Inverse Mix columns\n");
            printStateArray(stateArray);
            printf("Computing Inverse Shift Rows\n");
        }
        invShiftRows(stateArray,AES_BLOCK_SIZE);
        if(VERBOSE == 1) { 
            printf("State array after Inverse Shift Rows\n");
            printStateArray(stateArray);
            printf("Computing Inverse Sub bytes\n");
        }
        invSubBytes(stateArray);  
        if(VERBOSE == 1) {
            printf("State array after Inverse Sub Bytes\n");
            printStateArray(stateArray);
            printf("End of Round %d\n", rcounter+1);
        }                      
    }

    getRoundKey(expandedKey,tempKey,numRounds - rcounter-1);
    constructStateArray(tempKey,keyBlock); // flat to state
    AddRoundKey(stateArray,keyBlock);
    if(VERBOSE == 1) { 
        printf("Begin of Round %d\n", rcounter +1);
        printf("Round key for round %d\n", rcounter+1);
        printStateArray(keyBlock);
        printf("Computing add round key\n");
        printf("State array after Add round key\n");
        printStateArray(stateArray);  
         printf("End of Round %d\n", rcounter +1);      
    }
    // free all heap allocated memory 
    free(paddedCipherText);
    free(expandedKey);
    free(tempKey);
    free(paddedKey);

     // return plaintext
    unsigned char* plainText = calloc(AES_BLOCK_SIZE, sizeof(unsigned char));
    int counter = 0;
    for(int col = 0; col <4; col++) {
        for(int row = 0; row < 4; row++) {
            plainText[counter] = stateArray[row][col];
            counter++;
        }
    }

    if(VERBOSE == 1) {
        printf("\nResulting PlainText in Hexadecimal format is:\n");
        printAESBlock(plainText);
        printf("End of AES Decryption\n");
        printf("****************************************************************************************************************\n\n");
    } 
    return plainText;
}

/**
 * @brief RijndaelKeySchedule - Function that performs the Rijndael key scheduling for AES encryption. Takes in the 
 * original key passed in as parameter @param originalKey and the length of the original key given as parameter. 
 * The caller must free the memory allocated and returned.
 * @param originalKey - unsigned char * - An unsigned char pointer to the original key. 
 * @param keyLength - int - length of originalKey passed in as a parameter @param originalKey
 * @return expandedKey - The key that has been expanded. 
 */
unsigned char* RijndaelKeySchedule(unsigned char* originalKey, int keyLength)
{    
    uint8_t currentNumBytes = (keyLength); // number of bytes of the key we have so far
    uint8_t rConIter = 1; // counter for RCON
    int numRounds = getNumRounds(keyLength); // number of rounds of the encryption

    validateNumRounds(numRounds,keyLength);
    
    // we need 128 bits * (number of rounds +1) key at the end 
    uint8_t bytesNeeded =  ( (numRounds + 1) *AES_BLOCK_SIZE); 
    unsigned char* expandedKey = calloc(bytesNeeded, sizeof(char));
    for(uint8_t x = 0; x < keyLength; x++) {
        expandedKey[x] = originalKey[x];
    }

    int tempWordLength = 4; 
    unsigned char tempArr[tempWordLength]; // temp vector used for the keyExpansion

    // while number of bytes of key > number of bytes needed
    while(currentNumBytes < bytesNeeded) {
        // create 4 bytes 
        for(uint8_t x = 0; x < 4; x++) {
            tempArr[x] = expandedKey[(currentNumBytes - 4) + x];
        }
         /* every 16,24,32 bytes we apply the core schedule to t and increment rconIteration afterwards */
        if(currentNumBytes % keyLength == 0){
            KeyScheduleCore(tempArr, tempWordLength,rConIter);
            rConIter++;
        }
 
        /* For 256-bit keys, we add an extra sbox to the calculation */
        if(keyLength == 32 && ((currentNumBytes % keyLength) == 16)) {
            for(uint8_t x = 0; x < 4; x++) {
                tempArr[x] = getSBoxValue(tempArr[x]);
            }                
        }

        //  We XOR tempArr with the four-byte block 16,24,32 bytes before the new expanded key.
        //  This becomes the next four bytes in the expanded key.
        for(uint8_t x = 0; x < 4; x++) {
            expandedKey[currentNumBytes] = expandedKey[currentNumBytes - keyLength] ^ tempArr[x]; //Bitwise XOR
            currentNumBytes++;
        }
    } 
    return expandedKey;
} 

/**
 * @brief KeyScheduleCore - Function that performs the key schedule core for the Rijndael Key Schedule.
 * Performs a single rotate left of the word passed in as @param word and applies the required s-box substituion and rcon XOR. 
 * @param char - unsigned char* word - pointer to the word onto which the key schedule core should be operated. 
 * @param wordLength  - length of the word passed in as a parameter @param word. 
 * @param rConIterationVal - the iteration value to be used for the rcon XOR. 
 */
void KeyScheduleCore(unsigned char* word, int wordLength, int rConIterationVal)
{
    if(wordLength != 4) {
        printf("Error in Key Schedule Core, the word length is not 4 bytes it is %d bytes long\n", wordLength);
        printf("Exiting due to word length error in key schedule core");
        exit(EXIT_FAILURE);
    }
    // single rotate 
    SingleRotateLeft(word,wordLength);
    //apply S-Box substitution on all 4 parts of the 32-bit word
    for (uint8_t x = 0; x < 4; x++) {
        word[x] = getSBoxValue(word[x]);
    }
    //XOR the output of the rcon operation with i to the first part (leftmost) only
    word[0] = word[0]^getRconValue(rConIterationVal);
}


/**
 * @brief SingleRotateLeft - Function to rotate the array passed in as a paramter @param word, a single time left (8 bits to the left), 
 * with the left most element becoming the right most element. As such: rotate(1d2c3a4f) = 2c3a4f1d.  
 * @param word - unsigned char *word - the array/word to be left rotated by 8 bits. 
 * @param wordLength  - int - length of the parameter @param word. 
 */
void SingleRotateLeft(unsigned char *word,int wordLength)
{    
    if(wordLength != 4) {
        printf("Error in SingleRotateLeft, the word length is not 4 bytes it is %d bytes long\n", wordLength);
        printf("Exiting due to word length error in SingleRotateLeft");
        exit(EXIT_FAILURE);
    }

    unsigned char temp = word[0];
    for(uint8_t x = 0; x < 3; x++)
        word[x] = word[x+1];
    word[3] = temp;
}

/**
 * @brief printStateArray - Function to print the state array to the terminal in hex format.  
 * @param stateArray - the state array that should be printed to the terminal. 
 */
void printStateArray(uint8_t stateArray[4][4])
{   
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("%02X\t", stateArray[row][col]);
        }
        printf("\n");
    }
}

/**
 *  @brief AddRoundKey - Function that performs the Bitwise XOR between state and key as per AES encryption.
 *  @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption 
 *  @param key - unsigned char - sub key to be added for the current round to the current state vector
 */
void AddRoundKey(unsigned char state[4][4], unsigned char key[4][4])
{
    for(uint8_t row = 0; row < 4; row++) {
        for(uint8_t col = 0; col < 4; col++) {
            state[row][col] = state[row][col] ^ key[row][col];
        }
    }
}


/**
 * @brief mixColumns - Function that performs the MixColumns step of AES as specified by AES encryption.  
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption  
 */
void mixColumns(unsigned char state[4][4])
{
    for(int col = 0; col < 4; col++)
    {
        unsigned char tempState[4];

        for(int x = 0; x < 4; x++) {
            tempState[x] = state[x][col];
        }

        unsigned char copyTempState[4];
        unsigned char doubleTempState[4];

        for(size_t count = 0; count < 4; count++) {
            
            copyTempState[count] = tempState[count];
            /* arithmetic right shift, thus shifting in either zeros or ones */
            unsigned char msb = (unsigned char)((signed char)tempState[count] >> 7); 
            doubleTempState[count] = tempState[count] << 1; 
            doubleTempState[count] = doubleTempState[count] ^ 0x1B & msb; /* Rijndael's Galois field */
        }
        
        tempState[0] = doubleTempState[0] ^ copyTempState[3] ^ copyTempState[2] ^ doubleTempState[1] ^ copyTempState[1]; 
        tempState[1] = doubleTempState[1] ^ copyTempState[0] ^ copyTempState[3] ^ doubleTempState[2] ^ copyTempState[2]; 
        tempState[2] = doubleTempState[2] ^ copyTempState[1] ^ copyTempState[0] ^ doubleTempState[3] ^ copyTempState[3]; 
        tempState[3] = doubleTempState[3] ^ copyTempState[2] ^ copyTempState[1] ^ doubleTempState[0] ^ copyTempState[0]; 

        for(int x = 0; x < 4; x++) {
            state[x][col] = tempState[x];
        }
    }    
}

/**
 * @brief invMixColumns - Function that does the inverse of the Mix Column Step for AES Encryption. Performs the gallois field multiplication
 * and the required XOR to the state passed in as a paramter @param state. 
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption. 
 */
void invMixColumns(unsigned char state[4][4])
{   
    unsigned char placeHolderArray[4]; 
	for(size_t col = 0; col< 4; col++) {

		for(size_t row = 0; row < 4; row++) {
            placeHolderArray[row] = state[row][col];
        }

		for(size_t row =  0; row <4; row++) {
            // galois field multiplication
			state[row][col] = galloisFieldMult(0x0e, placeHolderArray[row]) ^ galloisFieldMult(0x0b, placeHolderArray[(row+1)%4]) ^ galloisFieldMult(0x0d, placeHolderArray[(row+2)%4]) ^ galloisFieldMult(0x09, placeHolderArray[(row+3)%4]);
		}
	}
}


/**
 * @brief galloisFieldMult - Function to perform the Galois field multiplication operation required for the inverse mix columns and the 
 * mix columns operation of the AES encryption and decryption processes. Returns the result of the multiplication. 
 * @param a - first character to perform Galois field multiplication. 
 * @param b - second character to perform Galois field multiplication. 
 * @return unsigned char - Result of the Galois field multiplication. 
 */
unsigned char galloisFieldMult(unsigned char a, unsigned char b)
{
    unsigned char tempArr[4];
	unsigned char product = 0;
	tempArr[0] = b;

	for(int i=1; i<4; i++) {
		tempArr[i] = tempArr[i-1] << 1; // left shift by one 
		if (tempArr[i-1]&0x80) {
            tempArr[i] = tempArr[i] ^ 0x1b;
        }		
	}

	for(int i = 0; i < 4; i++) {
        if( (a>>i) & 0x01) {
            product = product^tempArr[i];
        }
    }
	return product;
}

/**
 * @brief subBytes - Function that performs the sub byte operation where each value is replaced by the s box value
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption. 
 */
void subBytes(unsigned char state[4][4])
{
    for(uint8_t row = 0; row < 4; row++) {
        for(uint8_t col = 0; col < 4; col++) {
            state[row][col] = getSBoxValue(state[row][col]);
        }
    }
}

/**
 * @brief invSubBytes - Function that performs the inverse of Function subBytes  
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption
 */
void invSubBytes(unsigned char state[4][4])
{
     for(uint8_t row = 0; row < 4; row++) {
        for(uint8_t col = 0; col < 4; col++) {
            state[row][col] = getInvSBox(state[row][col]);
        }
    }
}

/**
 * @brief ShiftRows - Function to shift the state array according to the AES encryption standard for 128 - bits blocks
 * @param state - unsigned char -  is the current state of the ciphertext or plaintext during AES encryption or decryption 
 */
void ShiftRows(unsigned char state[4][4], int wordLength)
{
    //printf("In Shift Rows\n");
    if(wordLength != AES_BLOCK_SIZE) {
        printf("Error the plaintext block length is not valid, entered a block with length = %d characters\n", wordLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    for(uint8_t x = 1; x<4;x++) {
        for(uint8_t counter = 0; counter<x;counter++) {
            SingleRotateLeft(*(state+x),4);
        }
    }
}

/**
 * @brief invShiftRows - Function to shift the state array Inverse according to the AES encryption standard for 128 - bits blocks 
 * @param state - unsigned char - is the current state of the ciphertext or plaintext during AES encryption or decryption 
 */
void invShiftRows(unsigned char state[4][4], int wordLength)
{
    if(wordLength != AES_BLOCK_SIZE) {
        printf("Error the cipherText block length is not valid, entered a block with length = %d characters\n", wordLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    for(uint8_t x = 1; x<4;x++) {
        for(uint8_t counter = 0; counter<x;counter++) {
            SingleRotateRight(*(state+x),4);
        }
    }
}

/**
 * @brief SingleRotateRight - Function to rotate the array passed in as a paramter @param word, a single time right (8 bits to the right), 
 * with the right most element becoming the left most element. As such: rotate(1d2c3a4f) = 4f1d2c3a. 
 * 
 * @param word - unsigned char *word - the array/word to be right rotated by 8 bits. 
 * @param wordLength  - int - length of the parameter @param word. 
 */
void SingleRotateRight(unsigned char *word,int wordLength)
{    
    if(wordLength != 4) {
        printf("Error in SingleRotateLeft, the word length is not 4 bytes it is %d bytes long\n", wordLength);
        printf("Exiting due to word length error in SingleRotateLeft");
        exit(EXIT_FAILURE);
    }

    unsigned char temp = word[3];
    for(uint8_t x = 3; x > 0; x--) {
        word[x] = word[x-1];
    }

    word[0] = temp;
}


/**
 * @brief getRoundKey - Function to extract the correct sub-key to use for the appropriate round specified by @param
 * roundNum. Copies the sub-key from the expanded key in @param expandedKey to @param roundKey. 
 * @param char - expandedKey - The expanded key from which to extract the sub-key. 
 * @param char - roundKey - memory to which to copy the sub-key.
 * @param roundNum - int - the round number for which the sub-key is required. 
 */
void getRoundKey(unsigned char* expandedKey, unsigned char* roundKey, int roundNum)
{
    size_t keyIndex = roundNum*AES_BLOCK_SIZE;
    for(size_t x = 0; x < AES_BLOCK_SIZE; x++){
        roundKey[x] = expandedKey[keyIndex+x];
    }
}

/**
 * @brief constructStateArray - Function to convert the state array from a flat 1D array to a multidimensional array. 
 * 
 * @param char flatArray -the 1D array to be converted. 
 * @param stateArray - the multidimensional array to which to copy the flat array elements to. 
 */
void constructStateArray(unsigned char* flatArray, unsigned char stateArray[][4])
{
    for(uint8_t col = 0; col < 4; col++) {
        for(uint8_t row = 0; row < 4;row++) {
            stateArray[row][col] = flatArray[(4*col)+row];
        }
    }
}

/**
 * @brief hexToInt -  Function that converts a given hex value into an integer. 
 * @param ch - hex value that wil be converted to int. 
 * @return uint8_t the converted int value. 
 */
uint8_t hexToInt(char ch) 
{ 
    if(ch >=97) {
        ch = ch - 32;
    } 
    uint8_t first = (ch / 16) - 3;
    uint8_t second = ch % 16;
    uint8_t asciiChar = (first*10) + second;
    if(asciiChar > 9) {
        asciiChar--;
    }
    return asciiChar;
}

/**
 * @brief hexToAscii - Function that converts a given hex value to its ASCII equivalent.  
 * @param ch1 - char value of the first hex value.
 * @param ch2 - char value of the second hex value.
 */
uint8_t hexToAscii(char ch1, char ch2) 
{
        uint8_t highByte = hexToInt(ch1) * 16;
        uint8_t lowByte = hexToInt(ch2);
        return highByte + lowByte;
}


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
void hexToAsciiString(char* hexString, char* asciiString, int hexStringLength) 
{
	size_t asciiIndex = 0;
	char tempChar = 0;

	for (size_t x = 0; x < hexStringLength; x++) {
		if(x % 2 != 0) {
            asciiString[asciiIndex] = hexToAscii(tempChar, hexString[x]);
            asciiIndex++;
        } else {
            tempChar = hexString[x];
        }
	}
}

/**
 * @brief Function name: asciiToHexString - convert an ascii String to an ascii string. 
 * @param asciiString - unsigned char* pointing to the ASCII String to be converted. 
 * @param hexString  - unsigned char* pointing to a memory where the converted Hex string should be stored. 
 * @param asciiStringLen - size_t containing the length of the ASCII String to be converted. 
 * @return unsigned char* asciiToHexString - pointer to the converted Hex String, pointing to the same memory location
 * as @param hexString. 
 */
unsigned char* asciiToHexString(unsigned char *asciiString, unsigned char* hexString, size_t asciiStringLen)
{	
	if(asciiString == NULL || asciiStringLen == 0)
		return NULL;

	for(size_t x = 0; x < asciiStringLen; x++) {
        hexString[x*2]   = "0123456789abcdef"[asciiString[x] >> 4];
        hexString[x*2+1] = "0123456789abcdef"[asciiString[x] & 0x0F];
	}

    return hexString; 
}

/**
 * @brief validateNumRounds - Function that validates the number of rounds that have been passed in by the @param numRounds. Upon invalid validation,
 * relevent error information will be printed to terminal and the program will exit with an EXIT_FAILURE flag. 
 * @param numRounds - int - Integer value of the number rounds
 */
void validateNumRounds(int numRounds, int keyLength)
{
    if(numRounds == -1 ) {
        printf("Error the key length is not valid, greater than 256 bits\n"); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief validatePlainTextLength - Function that validates the length of the plaintext. The validation is done against the AES_BLOCK_SIZE value
 * @param plainTextLength - int - The length of the plaintext text as an integer value 
 */ 
void validatePlainTextLength(size_t plainTextLength)
{
    if(plainTextLength > AES_BLOCK_SIZE) {
        printf("Error the plaintext block length is not valid, entered a block with length = %ld characters\n", plainTextLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief validateCipherTextLength - Function that validates the length of the ciphertext. The validation is done against the AES_BLOCK_SIZE value
 * @param cipherTextLength - int - The length of the cipher text as an integer value 
 */ 
void validateCipherTextLength(int cipherTextLength)
{
    if(cipherTextLength > AES_BLOCK_SIZE) {
        printf("Error the cipherText block length is not valid, entered a block with length = %d characters\n", cipherTextLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief printAESBlock - Function to print a single block in hex format to the terminal.  
 * @param block - block to be printed. 
 */
void printAESBlock(unsigned char * block)
{
    for(int x  = 0; x<AES_BLOCK_SIZE;x++) {
        printf("%02X\t", block[x]);
    }
    printf("\n");
}

/**
 * @brief Returns the last index of '/' in a given path, otherwise returns -1 if no '/' is found 
 * 
 * @param fileName The path to a file
 * @param fileNameLength The length of the provided file
 * @return int Index of the last '/' in the path, else -1 if no '/' was found
 */
int fileNameDirIndex(char* fileName, int fileNameLength)
{
    int index = -1;
    for(int x = 0; x < fileNameLength; x++) {
        if(fileName[x] == '/') {
            index = x; 
        }
    }
    return index;
}

/**
 * @brief Removes path from the provided path to a file and returns only the file name
 * 
 * @param fileName The path to a specified file
 * @param extractedFileName The name of the file within the provided path to a file
 * @param extractedFilePath The path to file, excluding the file name
 * @param fileNameLength The length of the paramter @param fileName
 * @param slashIndex The index of the last '/' in the original file path passed in as a paramter @param fileName
 */
void stripDirectory(char * fileName, char* extractedFileName, char* extractedFilePath, int fileNameLength, int slashIndex)
{
    int counter = 0; 
    for(int x = slashIndex+1; x<fileNameLength || counter <= slashIndex;x++){
        
        if(x<fileNameLength) {
            extractedFileName[counter] = fileName[x];
        }
        if(counter <= slashIndex) {
            extractedFilePath[counter] = fileName[counter];
        }                
        counter++;
    }   
}

/**
 * @brief Get the output file name from all the parameters passed in
 * 
 * @param type 0 - Encrypt, 1 - Decrypt
 * @param fileName The name of the input file
 * @param outputFileName The name of the output file
 * @param mode Chipher mode to be used (ECB, CBC, CFB)
 */
void getOutputFileName(int type, char* fileName, char* outputFileName, char* mode)
{
    int slashIndex = fileNameDirIndex(fileName,strlen(fileName));
    
    if(slashIndex < 0) {
        if(type == 0) {
            if(strcmp(mode,"cbc") == 0){
                memcpy(outputFileName,"cbcEncrypted_", 500);
            } else if(strcmp(mode,"ecb") == 0){
                memcpy(outputFileName,"ecbEncrypted_", 500);
            } else if(strcmp(mode,"cfb") == 0){
                memcpy(outputFileName,"cfbEncrypted_", 500);
            } else{
                memcpy(outputFileName,"Encrypted_", 500);
            }
            
        } else{ 
            if(strcmp(mode,"cbc") == 0) {
                memcpy(outputFileName,"cbcDecrypted_", 500);
            } else if(strcmp(mode,"ecb") == 0) {
                memcpy(outputFileName,"ecbDecrypted_", 500);
            } else if(strcmp(mode,"cfb") == 0) {
                memcpy(outputFileName,"cfbDecrypted_", 500);
            } else {
                memcpy(outputFileName,"Decrypted_", 500);
            }
            
        }        
        strcat(outputFileName,fileName);
    } else {
        char* extractedFileName = calloc(strlen(fileName), sizeof(char));
        char* extractedFilePath = calloc(strlen(fileName), sizeof(char));

        stripDirectory(fileName,extractedFileName, extractedFilePath, strlen(fileName), slashIndex); 
        strcat(outputFileName,extractedFilePath);
        if(type == 0) {
            if(strcmp(mode,"cbc") == 0){
                strcat(outputFileName,"cbcEncrypted_");
            } else if(strcmp(mode,"ecb") == 0){
                strcat(outputFileName,"ecbEncrypted_");
            } else if(strcmp(mode,"cfb") == 0){
                strcat(outputFileName,"cfbEncrypted_");
            } else{
                strcat(outputFileName,"Encrypted_");
            }
            
        } else {
             if(strcmp(mode,"cbc") == 0){
                strcat(outputFileName,"cbcDecrypted_");
            } else if(strcmp(mode,"ecb") == 0){
                strcat(outputFileName,"ecbDecrypted_");
            } else if(strcmp(mode,"cfb") == 0){
                strcat(outputFileName,"cfbDecrypted_");
            } else{
                strcat(outputFileName,"Decrypted_");
            }
        }        
        strcat(outputFileName, extractedFileName);
        free(extractedFileName);
        free(extractedFilePath);
    }
}

/**
 * @brief isFileTxt - Function to determine if the file passed in as a paramter @param filename is a text file with extension
 * .txt or not. Returns a 1 if it is and a 0 if it isn't. 
 * 
 * @param fileName - unsigned char* fileName - path to file to determine if the file is a text file or not. 
 * @return uint8_t  - boolean indicating if it is a text file or not. (0 is not a text file, 1 is a text file)
 */
uint8_t isFileTxt(unsigned char * fileName)
{
    if(fileName == NULL || strlen(fileName) == 0) {
        return 0; 
    } else {
        unsigned char* temp = strrchr(fileName, '.');
        if(strcmp(temp+1, "txt") == 0) {
            return 1;
        }
    }
    return 0; 
}


/**
 * @brief keyHexToAscii - Function to convert a key from a Hex string passed in as a paramter @param
 * hexKey to an ascii string. User must free the returned pointer to memory allocated. 
 * Returns the Ascii equivalent. The caller must free the pointer returned. 
 * @param char - unsigned char* hexKey - hex representation of the key to be converted to ASCII. 
 * @param keyLength - length of the hex representation of the key passed in as paramter @param hexKey. 
 * @return unsigned* - the ASCII representation of the hex key passed in as parameter @param hexKey. 
 */
unsigned char* keyHexToAscii(unsigned char* hexKey, int keyLength) {
    
    keyLength = keyLength/2;
    int numRounds = getNumRounds(keyLength);
    // if ascii key length is valid, this will be the size of the ascii key buffer
    int tempKeyLength = getPaddedKeyLength(keyLength);
    // ascii key length must be valid
    if(numRounds != -1) {
        // allocate memory for the temp key
        unsigned char* tempKey = calloc(tempKeyLength,sizeof(char));
        // convert to ascii store in temp key
        hexToAsciiString(hexKey,tempKey,keyLength*2);
        return tempKey;
        // 
    } else {
        return hexKey;
    }
}

/**
 * @brief IVHexToAscii - Function to convert a initialization vector from a Hex string passed in as a paramter @param
 * hexIV to an ascii string. User must free the returned pointer to memory allocated. 
 * Returns the Ascii equivalent. The caller must free the pointer returned. 
 * @param char - unsigned char* hexIV - hex representation 
 * @param IVLength - length of the hex representation of the IV passed in as paramter @param hexIV. 
 * @return unsigned* - the ASCII representation of the hex IV passed in as parameter @param hexIV. 
 */
unsigned char* IVHexToAscii(unsigned char* hexIV, int IVLength)
{
    IVLength = IVLength/2;

    if(IVLength <= AES_BLOCK_SIZE) {
        unsigned char* tempIV = calloc(AES_BLOCK_SIZE,sizeof(char));
        // convert to ascii store in temp key
        hexToAsciiString(hexIV,tempIV,IVLength*2);
        return tempIV;

    } else { 
        return hexIV; // do nothing else since the check will be done again and end if appropriate
    }
}

/**
 * @brief XORBlocks - Function to XOR two blocks of length @param length and retuns the XOR'd result.
 * User must free the memory returned. 
 * @param char - block1 - First block to be XOR'd. 
 * @param char - block2 - Second block to be XOR'd. 
 * @param length - length of the blocks to be XOR'd. 
 * @return unsigned* - Result of the XOR.  
 */
unsigned char* XORBlocks(unsigned char* block1, unsigned char* block2, int length)
{
    unsigned char* result = calloc(length, sizeof(char));
    
    for(size_t x = 0; x < length; x++) {
        result[x] = block1[x] ^ block2[x];
    }
    return result;
}


