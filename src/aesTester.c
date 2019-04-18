// EHN 410 - Mohamed Ameen Omar - u16055323 - 2019

/**
 * @file AESTester.c
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

#include "stdio.h"
#include "AES.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

extern const unsigned char invSBox[256]; // inverse s box
extern const unsigned char sbox[256]; // s box lookup table
extern const unsigned char Rcon[255]; // rcon lookup table



int main(int argc, char * argv[])
{

    /***************** S BOX SUB TESTING ********************************/   

    /***
     * S Box test : 
     * Before (in hex) 00 3C 6E 47 1F 4E 22 74 0E 08 1B 31 54 59 0B 1A
     * After (in hex)  63 EB 9F A0 C0 2F 93 92 AB 30 AF C7 20 CB 2B A2
     * */
    printf("________________ SBox sub testing  ____________________\n");

    unsigned char before[] = {0x00,0x3C,0x6E,0x47,0x1F,0x4E,0x22,0x74,0x0E,0x08,0x1B,0x31,0x54,0x59, 0x0B,0x1A};
    printf("\nBefore s box sub:");
    for(int x =0; x < 16;x++){
        if(x % 4 == 0)
        {
            printf("\n");
        }
        printf("%X \t", before[x]);
    }

    printf("\nAfter s box sub:\n");
    for(int x =0; x < 16;x++){
        if(x % 4 == 0)
        {
            printf("\n");
        }
        printf("%X \t", getSBoxValue(before[x]));
    }
    printf("\n");
    printf("________________ SBox testing over ____________________\n\n");
    /***************** END S BOX SUB TESTING ********************************/  

    /***************** Key Expansion testing ********************************/  
    printf("_______________ Testing key expansion ____________________________\n");

    printf("_______________ START With 128 bit key of null chars (16 chars long) ______________________\n");
       /*
     Expanded key should be: 
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63 
                9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa 
                90 97 34 50 69 6c cf fa f2 f4 57 33 0b 0f ac 99 
                ee 06 da 7b 87 6a 15 81 75 9e 42 b2 7e 91 ee 2b 
                7f 2e 2b 88 f8 44 3e 09 8d da 7c bb f3 4b 92 90 
                ec 61 4b 85 14 25 75 8c 99 ff 09 37 6a b4 9b a7 
                21 75 17 87 35 50 62 0b ac af 6b 3c c6 1b f0 9b 
                0e f9 03 33 3b a9 61 38 97 06 0a 04 51 1d fa 9f 
                b1 d4 d8 e2 8a 7d b9 da 1d 7b b3 de 4c 66 49 41 
                b4 ef 5b cb 3e 92 e2 11 23 e9 51 cf 6f 8f 18 8e
    */

    int numChars = 16; 
    int numRounds = getNumRounds(numChars);
    printf("For a key with %d chars we have %d rounds as such we need %d bits of an expanded key in total and %d of bytes in total\n", numChars, numRounds, numChars*(numRounds+1)*8,numChars*(numRounds+1));
    printf("Before key expansion:\n");
    unsigned char key16Before[16];
    for(size_t x = 0; x<16;x++)
    {
        key16Before[x] = 0x00;
    }

    for(int x =0; x < 16;x++){
        if(x % 16 == 0)
        {
            printf("\n");
        }
        printf("%c \t", key16Before[x]);
    }
    printf("\n");

    printf("Performing key expansion\n");

    unsigned char * key16After = RijndaelKeySchedule(key16Before,16);
    

     for(int x =0; x < numChars*(numRounds+1);x++){
        if(x % 16 == 0)
        {
            printf("\n");
        }
        printf("%X \t", key16After[x]);
    }

    free(key16After);
    printf("\n_______________ END 128 bit key of null chars (16 chars long) ______________________\n");

    printf("\n_______________ START With 192 bit key of null chars (24 chars long) ______________________\n");
    /*
     Expanded key should be: 
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                00 00 00 00 00 00 00 00 62 63 63 63 62 63 63 63 
                62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63 
                9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa 
                9b 98 98 c9 f9 fb fb aa 90 97 34 50 69 6c cf fa 
                f2 f4 57 33 0b 0f ac 99 90 97 34 50 69 6c cf fa 
                c8 1d 19 a9 a1 71 d6 53 53 85 81 60 58 8a 2d f9 
                c8 1d 19 a9 a1 71 d6 53 7b eb f4 9b da 9a 22 c8 
                89 1f a3 a8 d1 95 8e 51 19 88 97 f8 b8 f9 41 ab 
                c2 68 96 f7 18 f2 b4 3f 91 ed 17 97 40 78 99 c6 
                59 f0 0e 3e e1 09 4f 95 83 ec bc 0f 9b 1e 08 30 
                0a f3 1f a7 4a 8b 86 61 13 7b 88 5f f2 72 c7 ca 
                43 2a c8 86 d8 34 c0 b6 d2 c7 df 11 98 4c 59 7
    */

    numChars = 24; 
    numRounds = getNumRounds(numChars);
    printf("For a key with %d chars we have %d rounds as such we need %d bits of an expanded key in total and %d of bytes in total\n", numChars, numRounds, numChars*(numRounds+1)*8,numChars*(numRounds+1));
    printf("Before key expansion:\n");
    unsigned char key24Before[24];
    for(size_t x = 0; x<24;x++)
    {
        key24Before[x] = 0x00;
    }

    for(int x =0; x < 24;x++){
        if(x % 16 == 0)
        {
            printf("\n");
        }
        printf("%X \t", key24Before[x]);
    }
    printf("\n");

    printf("Performing key expansion\n");

    unsigned char * key24After = RijndaelKeySchedule(key24Before,24);   

     for(int x =0; x < 16*(numRounds+1);x++){
        if(x % 16 == 0)
        {
            printf("\n");
        }
        printf("%X \t", key24After[x]);
    }
    free(key24After);
    printf("\n_______________ END 192 bit key of null chars (16 chars long) ______________________\n");

    


    printf("\n_______________ START With 256 bit key of null chars (32 chars long) ______________________\n");
    /*
     Expanded key should be: 
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63 
                aa fb fb fb aa fb fb fb aa fb fb fb aa fb fb fb 
                6f 6c 6c cf 0d 0f 0f ac 6f 6c 6c cf 0d 0f 0f ac 
                7d 8d 8d 6a d7 76 76 91 7d 8d 8d 6a d7 76 76 91 
                53 54 ed c1 5e 5b e2 6d 31 37 8e a2 3c 38 81 0e 
                96 8a 81 c1 41 fc f7 50 3c 71 7a 3a eb 07 0c ab 
                9e aa 8f 28 c0 f1 6d 45 f1 c6 e3 e7 cd fe 62 e9 
                2b 31 2b df 6a cd dc 8f 56 bc a6 b5 bd bb aa 1e 
                64 06 fd 52 a4 f7 90 17 55 31 73 f0 98 cf 11 19 
                6d bb a9 0b 07 76 75 84 51 ca d3 31 ec 71 79 2f 
                e7 b0 e8 9c 43 47 78 8b 16 76 0b 7b 8e b9 1a 62 
                74 ed 0b a1 73 9b 7e 25 22 51 ad 14 ce 20 d4 3b 
                10 f8 0a 17 53 bf 72 9c 45 c9 79 e7 cb 70 63 85
    */

    numChars = 32; 
    numRounds = getNumRounds(numChars);
    printf("For a key with %d chars we have %d rounds as such we need %d bits of an expanded key in total and %d of bytes in total\n", numChars, numRounds, numChars*(numRounds+1)*8,numChars*(numRounds+1));
    printf("Before key expansion:\n");
    unsigned char key32Before[32];
    for(size_t x = 0; x<32;x++)
    {
        key32Before[x] = 0x00;
    }

    for(int x =0; x < 32;x++){
        if(x % 16 == 0)
        {
            printf("\n");
        }
        printf("%X \t", key32Before[x]);
    }
    printf("\n");

    printf("Performing key expansion\n");

    unsigned char * key32After = RijndaelKeySchedule(key32Before,32);   

     for(int x =0; x < 16*(numRounds+1);x++){
        if(x % 16 == 0)
        {
            printf("\n");
        }
        printf("%X \t", key32After[x]);
    }
    free(key32After);
    printf("\n_______________ END 256 bit key of null chars (32 chars long) ______________________\n");


    printf("\n_______________ END Testing key expansion ____________________________\n");
    /***************** END Key Expansion testing ********************************/  

    /***************** START SHIFT ROWS testing ********************************/  
    

    printf("\n_______________ START Testing SHIFT ROWS ____________________________\n");
    unsigned char stateArr[4][4] = { 0xd4,0xe0,0xb8,0x1e,
                                 0x27,0xbf,0xb4,0x41,
                                 0x11,0x98,0x5d,0x52,
                                 0xae,0xf1,0xe5,0x30};  

/**
     * Result Should BE: 
     *  d4 e0 b8 1e
        bf b4 41 27
        5d 52 11 98
        30 ae f1 e5 
     */
    printf("Testing 1:\n");
    printf("Before: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", stateArr[row][col]);
        }
        printf("\n");
    }
    ShiftRows(stateArr,16);
    printf("After: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", stateArr[row][col]);
        }
        printf("\n");
    }
    printf("\n\n");

   unsigned char stateArr2[4][4] = {0xe9,0xcb,0x3d,0xaf,
                                    0x09,0x31,0x32,0x2e,
                                    0x89,0x07,0x7d,0x2c,
                                    0x72,0x5f,0x94,0xb5};
    /**
     * Result Should BE: 
     *  e9 cb 3d af
        31 32 2e 09
        7d 2c 89 07
        b5 72 5f 94
     */
    printf("Testing 2:\n");
    printf("Before: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", stateArr2[row][col]);
        }
        printf("\n");
    }
    ShiftRows(stateArr2,16);
    printf("After: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", stateArr2[row][col]);
        }
        printf("\n");
    }
    printf("\n\n");

     printf("\n_______________ END Testing SHIFT ROWS ____________________________\n");
     /***************** END SHIFT ROWS testing ********************************/  

    /***************** START SUB BYTES testing ********************************/  
    printf("\n_______________START SUB BYTES TESTING ____________________________\n");
	
/**
     * Result Should BE: 
     *      _20_	_B7_	_EF_	_8F_	
            _45_	_F9_	_B7_	_92_	
            _F9_	_8F_	_92_	_31_	
            _8F_	_B7_	_4D_	_31_
     */

    unsigned char subBytesTest[4][4] = {'T', ' ', 'a', 's',
                    'h','i',' ', 't',
                    'i', 's', 't', '.',
                    's', ' ', 'e', '.'};

    printf("Before \n ");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%c_\t", subBytesTest[row][col]);
        }
        printf("\n");
    }
    printf("\n\n");

    
    subBytes(subBytesTest);
    printf("After\n");
      for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", subBytesTest[row][col]);
        }
        printf("\n");
    }
     printf("_____________________ END SUB BYTES TESTING ____________________________\n");
    /***************** END SUB BYTES testing ********************************/ 



    /************* _______________START Add round key TESTING ____________________________*/
     printf("\n_______________START Add round key TESTING ____________________________\n");
	
    /**
    * Result Should BE: 
    * 00 3C 6E 47 
    * 1F 4E 22 74 
    * 0E 08 1B 31 
    * 54 59 0B 1A
    */
    unsigned char roundState[4][4] = {0x54,0x4F,0x4E,0x20,0x77,0x6E,0x69,0x54,0x6F,0x65,0x6E,0x77,0x20,0x20,0x65,0x6F};
    unsigned char roundKey[4][4] = {0x54,0x73,0x20,0x67,0x68,0x20,0x4B,0x20,0x61,0x6D,0x75,0x46,0x74,0x79,0x6E,0x75};

    printf("Before add roundkey: \n");
    printf("\nState: \n");
    for(size_t row = 0; row<4;row++){
        for(size_t col = 0; col< 4;col++)
        {
            printf("%X \t", roundState[row][col]);
        }
        printf("\n");
    }
    printf("\nKey:\n");
    for(size_t row = 0; row<4;row++){
        for(size_t col = 0; col< 4;col++)
        {
            printf("%X \t", roundKey[row][col]);
        }
        printf("\n");
    }
    AddRoundKey(roundState, roundKey);
    printf("\nAfter add roundkey: \n");
    for(size_t row = 0; row<4;row++){
        for(size_t col = 0; col< 4;col++)
        {
            printf("%X \t", roundState[row][col]);
        }
        printf("\n");
    }
    printf("\n");
     printf("_____________________ END Add round key TESTING ____________________________\n");
    /***************** END Add round key testing ********************************/ 



     /***************** START Mix COLUMNS TESTING ********************************/  
    printf("\n_______________START Mix COLUMNS TESTING ____________________________\n");
	
    /**
     * Result should be:
                4a a8 b3 7a
                6c 47 d8 c7
                5b cf 6 29
                7b 3a 3d 93
     */
    unsigned char mixColumnsTest[4][4] = {  0x74,0x20,0x61,0x73,
                                            0x68,0x69,0x20,0x74,
                                            0x69,0x73,0x74,0x2e,
                                            0x73,0x20,0x65,0x2e};
                                            
    printf("Before\n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", mixColumnsTest[row][col]);
        }
        printf("\n");
    }
    mixColumns(mixColumnsTest);
    printf("After\n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", mixColumnsTest[row][col]);
        }
        printf("\n");
    }


     printf("_____________________ END Mix COLUMNS TESTING ____________________________\n");
    /***************** END Mix COLUMNS TESTING********************************/ 

    /***************** Start Encryption TESTING ********************************/ 
    printf("_____________________ Start Encryption TESTING ____________________________\n");
    // Should be: 29 C3 50 5F 57 14 20 F6 40 22 99 B3 1A 02 D7 3A
    unsigned char PlainText[] = {0x54,0x77,0x6F,0x20,0x4F,0x6E,0x65,0x20,0x4E,0x69,0x6E,0x65,0x20,0x54,0x77,0x6F};
    unsigned char key[] = {0x54,0x68,0x61,0x74,0x73,0x20,0x6D,0x79,0x20,0x4B,0x75,0x6E,0x67,0x20,0x46,0x75};
    unsigned char* cipherText = calloc(16,sizeof(char));
    unsigned char* tempCipherText = AESEncrypt(PlainText,key,16,16);
    memcpy(cipherText,tempCipherText,16);
    printf("\nCipherText:\n");
    for(int x =0; x<16;x++)
    {
        printf("%X  ",cipherText[x]);
    }
    printf("\n");
    free(cipherText);
    free(tempCipherText);
    printf("_____________________ End Encryption TESTING ____________________________\n");
    /***************** End Encryption TESTING ********************************/ 




    /************************ 
     *          DECRYPITON TESTS:
     * 
     * *******************************/

      /***************** Inverse S BOX SUB TESTING ********************************/   

    /***
     * S Box test : 
     * After (in hex) 00 3C 6E 47 1F 4E 22 74 0E 08 1B 31 54 59 0B 1A
     * Before (in hex)  63 EB 9F A0 C0 2F 93 92 AB 30 AF C7 20 CB 2B A2
     * */
    printf("\n\n\n________________ Inverse SBox sub testing  ____________________\n");

    unsigned char ibefore[] = {0x63,0xEB,0x9F,0xA0,0xC0,0x2F,0x93,0x92,0xAB,0x30,0xAF,0xC7,0x20,0xCB,0x2B,0xA2};
    // After: {0x00,0x3C,0x6E,0x47,0x1F,0x4E,0x22,0x74,0x0E,0x08,0x1B,0x31,0x54,0x59, 0x0B,0x1A};
    printf("\nBefore s box sub:");
    for(int x =0; x < 16;x++){
        if(x % 4 == 0)
        {
            printf("\n");
        }
        printf("%X \t", ibefore[x]);
    }

    printf("\nAfter s box sub:\n");
    for(int x =0; x < 16;x++){
        if(x % 4 == 0)
        {
            printf("\n");
        }
        printf("%X \t", getInvSBox(ibefore[x]));
    }
    printf("\n");
    printf("________________ Inverse SBox testing over ____________________\n\n");
    /***************** END Inverse S BOX SUB TESTING ********************************/  

    /***************** START SHIFT Inverse ROWS testing ********************************/  
    

    printf("\n_______________ START Testing Inverse SHIFT ROWS ____________________________\n");
    unsigned char istateArr[4][4] =   {  0xd4,0xe0,0xb8,0x1e,
                                        0xbf,0xb4,0x41,0x27,
                                        0x5d,0x52,0x11,0x98,
                                        0x30,0xae,0xf1,0xe5};

/**
     * Result Should BE: 
     * { 0xd4,0xe0,0xb8,0x1e,
        0x27,0xbf,0xb4,0x41,
        0x11,0x98,0x5d,0x52,
        0xae,0xf1,0xe5,0x30};
     *  
     */
    printf("Testing 1:\n");
    printf("Before: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", istateArr[row][col]);
        }
        printf("\n");
    }
    invShiftRows(istateArr,16);
    printf("After: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", istateArr[row][col]);
        }
        printf("\n");
    }
    printf("\n\n");

   unsigned char istateArr2[4][4] = {
                                    0xe9,0xcb,0x3d,0xaf,
                                    0x31,0x32,0x2e,0x09,
                                    0x7d,0x2c,0x89,0x07,
                                    0xb5,0x72,0x5f,0x94 };
    /**
     * Result Should BE: 
     * {0xe9,0xcb,0x3d,0xaf,
        0x09,0x31,0x32,0x2e,
        0x89,0x07,0x7d,0x2c,
        0x72,0x5f,0x94,0xb5};
     *  
     */
    printf("Testing 2:\n");
    printf("Before: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", istateArr2[row][col]);
        }
        printf("\n");
    }
    invShiftRows(istateArr2,16);
    printf("After: \n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", istateArr2[row][col]);
        }
        printf("\n");
    }
    printf("\n\n");

     printf("\n_______________ END Testing Inverse SHIFT ROWS ____________________________\n");
     /***************** END Inverse SHIFT ROWS testing ********************************/  

    
    printf("\n_______________START Inverse Mix COLUMNS TESTING ____________________________\n");
	
    /**
     * Result should be:  { 0x74,0x20,0x61,0x73,
                            0x68,0x69,0x20,0x74,
                            0x69,0x73,0x74,0x2e,
                            0x73,0x20,0x65,0x2e };
     */
    unsigned char invmixColumnsTest[4][4] = { 0x4a,0xa8,0xb3,0x7a,
                                            0x6c,0x47,0xd8,0xc7,
                                            0x5b,0xcf,0x6,0x29,
                                            0x7b,0x3a,0x3d,0x93}; 
                                            
    printf("Before\n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", invmixColumnsTest[row][col]);
        }
        printf("\n");
    }

    invMixColumns(invmixColumnsTest);
    printf("After\n");
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            printf("_%X_\t", invmixColumnsTest[row][col]);
        }
        printf("\n");
    }

     printf("_____________________ END Inverse Mix COLUMNS TESTING ____________________________\n");
    /***************** END Inverse Mix COLUMNS TESTING********************************/ 

     /***************** Start Decryption TESTING ********************************/ 
    printf("\n_____________________ Start Decryption TESTING ____________________________\n");
    // Should be: 0x54,0x77,0x6F,0x20,0x4F,0x6E,0x65,0x20,0x4E,0x69,0x6E,0x65,0x20,0x54,0x77,0x6F
    unsigned char aesDecyptCipherText[] = {0x29,0xC3,0x50,0x5F,0x57,0x14,0x20,0xF6,0x40,0x22,0x99,0xB3,0x1A,0x02,0xD7,0x3A};
    unsigned char aesDecyptKey[] = {0x54,0x68,0x61,0x74,0x73,0x20,0x6D,0x79,0x20,0x4B,0x75,0x6E,0x67,0x20,0x46,0x75}; 

    unsigned char* aesdecryptPlainText = calloc(16,sizeof(char));
    unsigned char* tempPlainText = AESDecrypt(aesDecyptCipherText,aesDecyptKey,16,16);
    memcpy(aesdecryptPlainText,tempPlainText,16);
    printf("\nDecrypted Plaintext:\n");
    for(int x =0; x<16;x++)
    {
        printf("%02X\t",(aesdecryptPlainText[x]));
    }
    printf("\n");
    free(aesdecryptPlainText);
    free(tempPlainText);
    printf("_____________________ End Decryption TESTING ____________________________\n");
    /***************** End Decryption TESTING ********************************/ 
	
    // printf("\n_____________________ Start Hex to ascii string converstion____________________________\n");

    // unsigned char* inputHexString = "48656C6C6F20776F726C6421";
    
    // unsigned char* inputPlainTextString = calloc(strlen(inputHexString), sizeof(unsigned char));
    // hexToAsciiString(inputHexString,inputPlainTextString);
    // printf("Input hex string: _%s_\n", inputHexString);
    // printf("Input plainTextString string: _%s_\n", inputPlainTextString);

     printf("\n_____________________ Start ECB encryption testing TESTING ____________________________\n");
    
    unsigned char* keyBlock = calloc(16*2,sizeof(char));
    memcpy(keyBlock,"2b7e151628aed2a6abf7158809cf4f3c",16*2);
    //printf("Key block Hex String is: %s\n", keyBlock);
    unsigned char* keyBlockAscii = calloc(16,sizeof(char));
    hexToAsciiString(keyBlock,keyBlockAscii,16*2);
    //printf("key block ascii is %d\n", keyBlockAscii);
    unsigned char* plainTextHex;
    unsigned char* plainTextAscii;

    char* plainTextHexArr[4] = {"6bc1bee22e409f96e93d7e117393172a", "ae2d8a571e03ac9c9eb76fac45af8e51", "30c81c46a35ce411e5fbc1191a0a52ef","f69f2445df4f9b17ad2b417be66c3710"};
    for(int x = 0; x<4;x++)
    {
        plainTextHex = calloc(16*2,sizeof(char));
        plainTextAscii = calloc(16,sizeof(char));
        memcpy(plainTextHex,plainTextHexArr[x],16*2);
        hexToAsciiString(plainTextHex,plainTextAscii,16*2);
        unsigned char* cipherText = AESEncrypt(plainTextAscii,keyBlockAscii,16,16);
        //ecnrypt
        printf("Block %d, CipherText:\n", x+1);
        for(int z = 0; z<16;z++)
        {
            printf("%02X", cipherText[z]);
        }
        printf("\n");
        free(plainTextHex);
        free(plainTextAscii);
        free(cipherText);
    }
    free(keyBlock);
    free(keyBlockAscii);
    /* Expected CipherText: 
        3ad77bb40d7a3660a89ecaf32466ef97
        f5d3d58503b9699de785895a96fdbaaf
        43b1cd7f598ece23881b00e3ed030688
        7b0c785e27e8ad3f8223207104725dd4
    */
    printf("\n_____________________ Start END encryption testing TESTING ____________________________\n");


    printf("\n_____________________ Start ECB Decryption testing TESTING ____________________________\n");
    
    keyBlock = calloc(16*2,sizeof(char));
    memcpy(keyBlock,"2b7e151628aed2a6abf7158809cf4f3c",16*2);
    //printf("Key block Hex String is: %s\n", keyBlock);
    keyBlockAscii = calloc(16,sizeof(char));
    hexToAsciiString(keyBlock,keyBlockAscii,16*2);
    //printf("key block ascii is %d\n", keyBlockAscii);
    unsigned char* cipherTextHex;
    unsigned char* cipherTextAscii;

    unsigned char* cipherTextHexArr[4] = {"3ad77bb40d7a3660a89ecaf32466ef97", "f5d3d58503b9699de785895a96fdbaaf", "43b1cd7f598ece23881b00e3ed030688","7b0c785e27e8ad3f8223207104725dd4"};
    fflush(stdout);
    for(int x = 0; x<4;x++)
    {
        cipherTextHex = calloc(16*2+1,sizeof(char));
        cipherTextAscii = calloc(16+1,sizeof(char));
        memcpy(cipherTextHex,cipherTextHexArr[x],16*2);
        hexToAsciiString(cipherTextHex,cipherTextAscii,16*2);
        unsigned char* plainText = AESDecrypt(cipherTextAscii,keyBlockAscii,16,16);
        printf("Block %d, plainText:\n", x+1);
        for(int z = 0; z<16;z++)
        {
            printf("%02X", plainText[z]);
        }
        printf("\n");
        free(cipherTextHex);
        free(cipherTextAscii);
        free(plainText);
    }
    free(keyBlock);
    free(keyBlockAscii);
    /* Expected plainText: 
        6bc1bee22e409f96e93d7e117393172a
        ae2d8a571e03ac9c9eb76fac45af8e51
        30c81c46a35ce411e5fbc1191a0a52ef
        f69f2445df4f9b17ad2b417be66c3710
    */
    printf("\n_____________________ Start END decryption testing TESTING ____________________________\n");

    printf("\n_____________________ Start 192 key - ECB encryption testing TESTING ____________________________\n");
    
    keyBlock = calloc(24*2+1,sizeof(char));
    memcpy(keyBlock,"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",24*2);
    //printf("Key block Hex String is: %s\n", keyBlock);
    keyBlockAscii = calloc(24,sizeof(char));
    hexToAsciiString(keyBlock,keyBlockAscii,24*2);
    //printf("key block ascii is %d\n", keyBlockAscii);

    plainTextHexArr[0] = "6bc1bee22e409f96e93d7e117393172a";
    plainTextHexArr[1] =  "ae2d8a571e03ac9c9eb76fac45af8e51";
    plainTextHexArr[2] =   "30c81c46a35ce411e5fbc1191a0a52ef";
    plainTextHexArr[3] = "f69f2445df4f9b17ad2b417be66c3710";
    
    for(int x = 0; x<4;x++)
    {
        plainTextHex = calloc(16*2+1,sizeof(char));
        plainTextAscii = calloc(16+1,sizeof(char));
        memcpy(plainTextHex,plainTextHexArr[x],16*2);
        hexToAsciiString(plainTextHex,plainTextAscii,16*2);
        unsigned char* cipherText = AESEncrypt(plainTextAscii,keyBlockAscii,16,24);
        //ecnrypt
        printf("Block %d, CipherText:\n", x+1);
        for(int z = 0; z<16;z++)
        {
            printf("%02X", cipherText[z]);
        }
        printf("\n");
        free(plainTextHex);
        free(plainTextAscii);
        free(cipherText);
    }
    free(keyBlock);
    free(keyBlockAscii);
    /* Expected CipherText: 
        bd334f1d6e45f25ff712a214571fa5cc
        974104846d0ad3ad7734ecb3ecee4eef
        ef7afd2270e2e60adce0ba2face6444e
        9a4b41ba738d6c72fb16691603c18e0e
    */
    printf("\n_____________________ Start END 192 encryption testing TESTING ____________________________\n");

    
    printf("\n_____________________ Start 192 key ECB Decryption testing TESTING ____________________________\n");
    
    keyBlock = calloc(24*2+1,1);
    memcpy(keyBlock,"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",24*2+1);
    //printf("Key block Hex String is: %s\n", keyBlock);
    keyBlockAscii = calloc(16+1,1);
    hexToAsciiString(keyBlock,keyBlockAscii,24*2+1);
    //printf("key block ascii is %d\n", keyBlockAscii);
    cipherTextHex;
    cipherTextAscii;

    cipherTextHexArr[0] = "bd334f1d6e45f25ff712a214571fa5cc";
    cipherTextHexArr[1] =  "974104846d0ad3ad7734ecb3ecee4eef";
    cipherTextHexArr[2] =   "ef7afd2270e2e60adce0ba2face6444e";
    cipherTextHexArr[3] = "9a4b41ba738d6c72fb16691603c18e0e";
    

    for(int x = 0; x<4;x++)
    {
        cipherTextHex = calloc(16*2+1,1);
        cipherTextAscii = calloc(16+1,1);
        memcpy(cipherTextHex,cipherTextHexArr[x],16*2+1);
        hexToAsciiString(cipherTextHex,cipherTextAscii,16*2);
        unsigned char* plainText = AESDecrypt(cipherTextAscii,keyBlockAscii,16,24);
        printf("Block %d, plainText:\n", x+1);
        for(int z = 0; z<16;z++)
        {
            printf("%02X", plainText[z]);
        }
        printf("\n");
        free(cipherTextHex);
        free(cipherTextAscii);
        free(plainText);
    }
    free(keyBlock);
    free(keyBlockAscii);
    /* Expected plainText: 
        6bc1bee22e409f96e93d7e117393172a
        ae2d8a571e03ac9c9eb76fac45af8e51
        30c81c46a35ce411e5fbc1191a0a52ef
        f69f2445df4f9b17ad2b417be66c3710
    */
    printf("\n_____________________ END 192decryption testing TESTING ____________________________\n");

    printf("\n_____________________ Start 256 key - ECB encryption testing TESTING ____________________________\n");
    
    keyBlock = calloc(32*2+1,sizeof(char));
    memcpy(keyBlock,"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 ",32*2);
    //printf("Key block Hex String is: %s\n", keyBlock);
    keyBlockAscii = calloc(32,sizeof(char));
    hexToAsciiString(keyBlock,keyBlockAscii,32*2);
    //printf("key block ascii is %d\n", keyBlockAscii);
    plainTextHex;
    plainTextAscii;

    plainTextHexArr[0] = "6bc1bee22e409f96e93d7e117393172a";
    plainTextHexArr[1] =  "ae2d8a571e03ac9c9eb76fac45af8e51";
    plainTextHexArr[2] =   "30c81c46a35ce411e5fbc1191a0a52ef";
    plainTextHexArr[3] = "f69f2445df4f9b17ad2b417be66c3710";
    
    for(int x = 0; x<4;x++)
    {
        plainTextHex = calloc(16*2+1,sizeof(char));
        plainTextAscii = calloc(16+1,sizeof(char));
        memcpy(plainTextHex,plainTextHexArr[x],16*2);
        hexToAsciiString(plainTextHex,plainTextAscii,16*2);
        unsigned char* cipherText = AESEncrypt(plainTextAscii,keyBlockAscii,16,32);
        //ecnrypt
        printf("Block %d, CipherText:\n", x+1);
        for(int z = 0; z<16;z++)
        {
            printf("%02X", cipherText[z]);
        }
        printf("\n");
        free(plainTextHex);
        free(plainTextAscii);
        free(cipherText);
    }
    free(keyBlock);
    free(keyBlockAscii);

    /* Expected CipherText: 
        F3EED1BDB5D2A03C064B5A7E3DB181F8
        591CCB10D410ED26DC5BA74A31362870
        B6ED21B99CA6F4F9F153E7B1BEAFED1D
        23304B7A39F9F3FF067D8D8F9E24ECC7
    */

    printf("\n_____________________ Start END 256 encryption testing TESTING ____________________________\n");

        printf("\n_____________________ Start 256 key ECB Decryption testing TESTING ____________________________\n");
    
    keyBlock = calloc(32*2+1,1);
    memcpy(keyBlock,"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 ",32*2);
    //printf("Key block Hex String is: %s\n", keyBlock);
    keyBlockAscii = calloc(32,1);
    hexToAsciiString(keyBlock,keyBlockAscii,32*2);
    //printf("key block ascii is %d\n", keyBlockAscii);
    cipherTextHex;
    cipherTextAscii;

    cipherTextHexArr[0] = "f3eed1bdb5d2a03c064b5a7e3db181f8";
    cipherTextHexArr[1] =  "591ccb10d410ed26dc5ba74a31362870";
    cipherTextHexArr[2] =   "b6ed21b99ca6f4f9f153e7b1beafed1d";
    cipherTextHexArr[3] = "23304b7a39f9f3ff067d8d8f9e24ecc7";
    

    for(int x = 0; x<4;x++)
    {
        cipherTextHex = calloc(16*2+1,1);
        cipherTextAscii = calloc(16+1,1);
        memcpy(cipherTextHex,cipherTextHexArr[x],16*2);
        hexToAsciiString(cipherTextHex,cipherTextAscii,16*2);
        unsigned char* plainText = AESDecrypt(cipherTextAscii,keyBlockAscii,16,32);
        printf("Block %d, plainText:\n", x+1);
        for(int z = 0; z<16;z++)
        {
            printf("%02X", plainText[z]);
        }
        printf("\n");
        free(cipherTextHex);
        free(cipherTextAscii);
        free(plainText);
    }
    free(keyBlock);
    free(keyBlockAscii);
    /* Expected plainText: 
        6BC1BEE22E409F96E93D7E117393172A
        AE2D8A571E03AC9C9EB76FAC45AF8E51
        30C81C46A35CE411E5FBC1191A0A52EF
        F69F2445DF4F9B17AD2B417BE66C3710

    */
    printf("\n_____________________ END 256 decryption testing TESTING ____________________________\n");

    return 0;

}
