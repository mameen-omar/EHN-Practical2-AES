// EHN 410 - Mohamed Ameen Omar - u16055323 - 2019

/**
 * @file serverMain.c
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

/***
 *      IGNORE THIS FILE, USE FOR RANDOM TESTS AND PLAY AROUND CODE. 
 * 
 *      FEEL FREE TO EDIT and USE FOR ANYTHING. 
 * 
 *      WILL NOT BE USED IN THE FINAL PROGRAM
 */ 


#include "stdio.h"
#include "AES.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern const int AES_BLOCK_SIZE; // number of blocks in bits
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
        printf("%X \t", key16Before[x]);
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

     /***************** START Mix COLUMNS TESTING ********************************/  
    printf("\n_______________START Mix COLUMNS TESTING ____________________________\n");
	
    /**
     * Result should be:
                4a a8 b3 7a
                6c 47 d8 c7
                5b cf 6 29
                7b 3a 3d 93
     */
    unsigned char mixColumnsTest[4][4] = {    0x74,0x20,0x61,0x73,
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
    unsigned char* cipherText = AESEncrypt(PlainText,key,16,16);
    printf("\nCipherText:\n");
    for(int x =0; x<16;x++)
    {
        printf("%X  ",cipherText[x]);
    }
    printf("\n");
    free(cipherText);
    printf("_____________________ End Encryption TESTING ____________________________\n");
    /***************** End Encryption TESTING ********************************/ 

	return 0;
}
