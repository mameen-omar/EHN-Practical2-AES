/**
 * @file ecb.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Electronic code book (ECB) - AES Implementation file
 * This file contains the implementation of the functions used for the ECB mode of AES encryption. 
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

#include "ecb.h"


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
                int plainTextLength, int keyLength, int isTextHex, int isKeyHex)
{
    unsigned char* asciiPlainText; 
    unsigned char* asciiKey;
    printf("Start AES ECB Encryption\n");
    if(isTextHex == 1) {        
        plainTextLength = plainTextLength/2;
        unsigned char* tempText = calloc(plainTextLength,sizeof(char));
        // convert to ascii store in temp text
        hexToAsciiString(plainText,tempText,plainTextLength*2);
        asciiPlainText = tempText;
    } else {
        asciiPlainText = plainText; 
    }

    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    keyLength = getPaddedKeyLength(keyLength);

    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);
    // end check key length 

    unsigned char* paddedKey = calloc((keyLength), sizeof(unsigned char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey, asciiKey, keyLength); 

    int blockCounter = 0; 
    int blockNum = 0;

    printf("ECB Ciphertext output:\n");
    // encrypt and output in blocks
    while(1) {
        printf("Block %d:\n", blockNum+1);
        unsigned char* tempPlainText = calloc(AES_BLOCK_SIZE,sizeof(char));
        
        int x = 0;
        for(; x < AES_BLOCK_SIZE; x++) {
            if(blockCounter >= plainTextLength)
                break;
            tempPlainText[x] = asciiPlainText[blockCounter++];
        }
        // we have temp plainText 
        
        ecbEcryptHelper(tempPlainText, paddedKey, x, keyLength);
        free(tempPlainText);
        if(blockCounter >= plainTextLength)
            break;  
        blockNum++;
    }

    free(paddedKey);
    if(isTextHex == 1) {
        free(asciiPlainText);
    }
    
    if(isKeyHex == 1) {
        free(asciiKey);
    }

    printf("End AES ECB Encryption\n");
    
}

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
                int cipherTextLength, int keyLength, int isTextHex, int isKeyHex)
{
    unsigned char* asciiCipherText; 
    unsigned char* asciiKey;
    printf("Start AES ECB Decryption\n");
    if(isTextHex == 1) {        
        cipherTextLength = cipherTextLength/2;
        unsigned char* tempText = calloc(cipherTextLength,sizeof(char));
        // convert to ascii store in temp text
        hexToAsciiString(cipherText,tempText,cipherTextLength*2);
        asciiCipherText = tempText;
    } else {
        asciiCipherText = cipherText; 
    }

    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    keyLength = getPaddedKeyLength(keyLength);
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);

    unsigned char* paddedKey = calloc((keyLength), sizeof(unsigned char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey, asciiKey, keyLength);  

    int blockCounter = 0; 
    int blockNum = 0;
    printf("ECB PlainText Output:\n");
    // encrypt and output in blocks
    while(1) {
        printf("Block %d:\n", blockNum+1);
        unsigned char* tempCipherText = calloc(AES_BLOCK_SIZE,sizeof(char));
        int x = 0;
        for(; x < AES_BLOCK_SIZE; x++) {
            if(blockCounter >= cipherTextLength)
                break;
            tempCipherText[x] = asciiCipherText[blockCounter++];
        }
        ecbDecryptHelper(tempCipherText, paddedKey, x, keyLength);
        free(tempCipherText);
        if(blockCounter >= cipherTextLength)
            break;  
        blockNum++;
    }

    free(paddedKey);
    if(isTextHex == 1) {
        free(asciiCipherText);
    }
    
    if(isKeyHex == 1) {
        free(asciiKey);
    }
    printf("End AES ECB Decryption\n");
}

/**
 * @brief ecbEcryptHelper - Helper function used to encrypt the plaintext pointed to by @param plainText using ECB mode of encryption 
 * and output the result to the terminal. Encrypts a single block of 16 bytes using AES encryption.
 * @param char - unsigned char* plainText - the block input to be encrypted. 
 * @param char - unsigned char* key - the key to use for encryption. 
 * @param plainTextLength - int - the length of the plaintext to be encrypted in @param plainText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 */
void ecbEcryptHelper(unsigned char* plainText, unsigned char* key, int plainTextLength,int keyLength)
{ 
    unsigned char *cipherText = AESEncrypt(plainText,key,plainTextLength,keyLength);
    printAESBlock(cipherText);
    free(cipherText);
}

/**
 * @brief ecbDecryptHelper - Helper function used to decrypt the ciphertext pointed to by @param cipherText using ECB mode of decryption 
 * and output the result to the terminal. Decrypts a single block of 16 bytes using AES decryption.
 * @param char - unsigned char* cipherText - the block input to be encrypted. 
 * @param char - unsigned char* key - the key to use for decryption. 
 * @param cipherTextLength - int - the length of the ciphertext to be encrypted in @param cipherText. 
 * @param keyLength - int - the length of the key specified in @param key. 
 */
void ecbDecryptHelper(unsigned char* cipherText, unsigned char* key, int cipherTextLength,int keyLength)
{
    unsigned char *plainText = AESDecrypt(cipherText,key,cipherTextLength,keyLength);
    printAESBlock(plainText);
    free(plainText);
}


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
void ecbEncryptFile(unsigned char* fileName, unsigned char* key, int keyLength, int isTextHex, int isKeyHex)
{
    unsigned char* asciiKey;
    printf("Start AES ECB File Encryption\n");

     if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    keyLength = getPaddedKeyLength(keyLength);
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);

    FILE *filePointer;
    filePointer = fopen(fileName, "rb"); //read as a binary file

    if(filePointer == NULL) {
        printf("File not found, exiting\n");
        exit(EXIT_FAILURE);
    }

    if(VERBOSE == 1) { 
        printf("Input File opened successfully\n");
    }   

    FILE *outputFilePointer;
    char* outputFileName = calloc(500,sizeof(char)); 
    getOutputFileName(0,fileName,outputFileName, "ecb");
    outputFilePointer = fopen(outputFileName, "wb"); // open file

    if(filePointer == NULL) {
        printf("Error: Could not create output file, exiting\n");
        free(outputFileName);
        exit(EXIT_FAILURE);
    }

    if(VERBOSE == 1) {
        printf("Output file created successfully\n");
    }

    unsigned char* paddedKey = calloc((keyLength) ,sizeof(unsigned char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,asciiKey,keyLength);

    unsigned char* plainTextBlock;
    size_t readBufferLength; 


    if(isTextHex) {
        unsigned char* tempText = calloc(AES_BLOCK_SIZE*2, sizeof(char));
        readBufferLength = fread(tempText, sizeof(char), AES_BLOCK_SIZE*2, filePointer); // read 32 hex vals at a time
        plainTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        readBufferLength = readBufferLength/2;
        hexToAsciiString(tempText,plainTextBlock,readBufferLength*2);
        free(tempText);

    } else { 
        plainTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        readBufferLength = fread(plainTextBlock, sizeof(char), AES_BLOCK_SIZE, filePointer); // read 16 chars at a time - 128 bits
    }

    // padded plain text in case it is less than 16 chars
    unsigned char* paddedPlainText = calloc(AES_BLOCK_SIZE, sizeof(char));
    memcpy(paddedPlainText,plainTextBlock,AES_BLOCK_SIZE); //destination, source
    free(plainTextBlock); 
    plainTextBlock = NULL;
    int numberOfReads = 1;
    if(VERBOSE == 1) {
        printf("Reading block number %d from file\n", numberOfReads);
        printf("Plaintext block number %d in HEX format is: \n", numberOfReads);
        printAESBlock(paddedPlainText);
    }
    unsigned char* cipherTextBlock; //encrypted ciphertext for current block
    
    while(readBufferLength > 0) {
        
        if(VERBOSE == 1) {
            printf("Plaintext is: \n");
            printAESBlock(paddedPlainText);
            printf("Encrypting the plaintext\n\n");            
        }
        // encrypt result
        cipherTextBlock = AESEncrypt(paddedPlainText,paddedKey,AES_BLOCK_SIZE, keyLength);  // need to free unsigned char* plainText, unsigned char* key, int plainTextLength,int keyLength
        // write only the ascii - commented out the hex conversion
        int temp = fwrite(cipherTextBlock,sizeof(char),AES_BLOCK_SIZE, outputFilePointer); // cipherTextblock will always be 16 
        
        if(VERBOSE == 1) {
            printf("Writing Ciphertext block number %d to file in ASCII format (ASCII encoded)\n", numberOfReads);
        }
        free(cipherTextBlock); // free memory for previous cipherText from AES encrypt
        cipherTextBlock = NULL; 
        // read next plaintext block
        if(isTextHex) {
            unsigned char* tempText = calloc(AES_BLOCK_SIZE*2, sizeof(char));
            readBufferLength = fread(tempText, sizeof(char), AES_BLOCK_SIZE*2, filePointer); // read 32 hex vals at a time
            plainTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
            readBufferLength = readBufferLength/2;
            hexToAsciiString(tempText,plainTextBlock,readBufferLength*2);
            free(tempText);
         } else { 
            plainTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
            readBufferLength = fread(plainTextBlock, sizeof(char), AES_BLOCK_SIZE, filePointer); // read 16 chars at a time - 128 bits
        }
        numberOfReads++;
        
        // padded plain text in case it is less than 16 chars
        free(paddedPlainText);
        paddedPlainText = NULL;
        paddedPlainText = calloc(AES_BLOCK_SIZE, sizeof(char));
        memcpy(paddedPlainText,plainTextBlock,AES_BLOCK_SIZE); // padded plain text is the new block's plaintext with 0 padding
        free(plainTextBlock); // free initial read from file
        plainTextBlock = NULL;
        if(VERBOSE == 1 && readBufferLength > 0) {
            printf("Reading block number %d from file\n", numberOfReads);
            printf("Plaintext block number %d in HEX format is: \n", numberOfReads);
            printAESBlock(paddedPlainText);
        }
    }

    //free memory
    free(paddedKey);
    free(paddedPlainText);
    free(outputFileName);

    if(isKeyHex == 1) {
        free(asciiKey);
    }

    //close the file to be encrypted
    fclose(filePointer); 
    // close output file 
    fclose(outputFilePointer); 
    printf("End AES ECB File Encryption\n");
}

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
void ecbDecryptFile(unsigned char* fileName, unsigned char* key, int keyLength, int isTextHex, int isKeyHex)
{
    printf("Start ECB AES File Decryption\n");

    unsigned char* asciiKey; 

    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    keyLength = getPaddedKeyLength(keyLength);
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);
    // end check key length 
    
    /* Open file */ 
    FILE *filePointer;
    filePointer = fopen(fileName, "rb"); //read as a binary file

    if(filePointer == NULL) {
        printf("File not found, exiting\n");
        exit(EXIT_FAILURE);
    } 

    if(VERBOSE == 1){ 
        printf("Input File opened successfully\n");
    }

    FILE *outputFilePointer;
    char* outputFileName = calloc(500,sizeof(char)); 
    getOutputFileName(1,fileName,outputFileName, "ecb"); //decrypt
    
    outputFilePointer = fopen(outputFileName, "wb"); // open file
    if(filePointer == NULL) {
        printf("Error: Could not create output file, exiting\n");
        free(outputFileName);
        exit(EXIT_FAILURE);
    }   
    if(VERBOSE == 1) {
        printf("Output file created successfully\n");
    }
    unsigned char* paddedKey = calloc((keyLength) ,sizeof(char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,asciiKey,keyLength);  


    // read from file and sort out padding

    // now in decrypt, it and is stored as hex, need to read 32, convert to ascii, decrypt, convert back to hex and write
    
    unsigned char* cipherTextBlock; 
    size_t readBufferLength;

    if(isTextHex) {
        unsigned char* tempText = calloc(AES_BLOCK_SIZE*2, sizeof(char));
        readBufferLength = fread(tempText, sizeof(char), AES_BLOCK_SIZE*2, filePointer); // read 32 hex vals at a time
        cipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        readBufferLength = readBufferLength/2;
        hexToAsciiString(tempText,cipherTextBlock,readBufferLength*2);
        free(tempText);

    } else { 
        cipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        readBufferLength = fread(cipherTextBlock, sizeof(char), AES_BLOCK_SIZE, filePointer); // read 16 chars at a time - 128 bits
    }

    unsigned char* paddedCipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
    memcpy(paddedCipherTextBlock,cipherTextBlock,AES_BLOCK_SIZE); //destination, source
    free(cipherTextBlock); 
    cipherTextBlock = NULL;

    int numberOfReads = 1;
    if(VERBOSE == 1) {
        printf("Reading block number %d from file\n", numberOfReads);
        printf("Ciphertext block number %d in HEX format is: \n", numberOfReads);
        printAESBlock(paddedCipherTextBlock);
    }

    unsigned char* plainTextBlock; //decrypted plaintext for current block

    while(readBufferLength > 0) {
        
        if(VERBOSE == 1) {
            printf("Decrypting the Ciphertext block number %d\n", numberOfReads);
        }
        // XOR p1 and IV - both of length AES_BLOCK_SIZE
        plainTextBlock = AESDecrypt(paddedCipherTextBlock,paddedKey,AES_BLOCK_SIZE, keyLength);   
        
        if(VERBOSE == 1) {
            printf("Decrypted Plaintext number %d) is:\n", numberOfReads);
            printAESBlock(plainTextBlock);
        }
        
        // need to write back as hex 
        // write plainText to file
        int bytesToWrite = 0;
        if(isTextHex) {
            // convert to hex, check zero padding? write double
            // convert to hex, write double length
            unsigned char* hexString = calloc(AES_BLOCK_SIZE*2, sizeof(char));
            asciiToHexString(plainTextBlock, hexString, AES_BLOCK_SIZE); 
            fwrite(hexString,sizeof(char),AES_BLOCK_SIZE*2, outputFilePointer);
            free(hexString);
            if(VERBOSE == 1) {
                printf("Writing Plaintext block number %d to file in HEX format (Hex encoded)\n", numberOfReads);
            }
            
        } else {
            // text is not hex and the file is txt, dont write padding  - remove zero padding
            if(isFileTxt(fileName) == 1) {
                    // check for zero padding
                for(; bytesToWrite < AES_BLOCK_SIZE; bytesToWrite++) {
                    if(plainTextBlock[bytesToWrite] == 0x00)
                        break;
                }            
            } else {
                bytesToWrite = AES_BLOCK_SIZE; // we write the whole block 
            }

            if(VERBOSE == 1) {
                printf("Writing Plaintext block number %d to file in ASCII format (ASCII encoded)\n", numberOfReads);
            }
            // write back
            fwrite(plainTextBlock,sizeof(char),bytesToWrite, outputFilePointer); // plainTextBlock will always be 16 bytes    
        } // end of isTexHex if statement
        
        free(plainTextBlock); 

        free(paddedCipherTextBlock); // free memory for previous cipherText from AES encrypt
        paddedCipherTextBlock = NULL; 
        // read next plaintext block
        if(isTextHex) {
            unsigned char* tempText = calloc(AES_BLOCK_SIZE*2, sizeof(char));
            readBufferLength = fread(tempText, sizeof(char), AES_BLOCK_SIZE*2, filePointer); // read 32 hex vals at a time
            cipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
            readBufferLength = readBufferLength/2;
            hexToAsciiString(tempText,cipherTextBlock,readBufferLength*2);
            free(tempText);

        } else { 
            cipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
            readBufferLength = fread(cipherTextBlock, sizeof(char), AES_BLOCK_SIZE, filePointer); // read 16 chars at a time - 128 bits
        }
        // padded plain text in case it is less than 16 chars
        paddedCipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        memcpy(paddedCipherTextBlock,cipherTextBlock,AES_BLOCK_SIZE); // padded cipher text is the new block's plaintext with 0 padding
        free(cipherTextBlock); // free initial read from file
        cipherTextBlock = NULL;
        numberOfReads++;
        if(VERBOSE == 1 && readBufferLength > 0) {
            printf("Reading block number %d from file\n", numberOfReads);
            printf("Ciphertext block number %d in HEX format is: \n", numberOfReads);
            printAESBlock(paddedCipherTextBlock);
        }
    }

    //free memory
    free(paddedKey);
    free(paddedCipherTextBlock);
    free(outputFileName);

    if(isKeyHex) {
        free(asciiKey);
    }

    //close the file to be encrypted
    fclose(filePointer); 
    // close output file 
    fclose(outputFilePointer); 
    printf("End of ECB AES File Decryption\n");
}
