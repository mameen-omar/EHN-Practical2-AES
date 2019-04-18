// Mohamed Ameen Omar (u16055323)
/**
 * @file cbc.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Cipher Block Chaining (CBC) - AES Implementation file
 * This file contains the implementation of the functions used for the CBC mode of AES encryption. 
 * This system supports both file and user input encryption, as hex or ascii input. 
 * If the user inputs data to be encrypted or decrypted, the result will be printed to the terminal, whereas 
 * if the user specifies a file to be encrypted or decrypted, a new file will be created and the result will be written
 * to the file. 
 * The CBC Encryption platform encrypts and decrypts blocks 16 bytes at a time, using 0 padding. 
 * The IV is limited to 16 bytes and the key is limited to 32 bytes as per the AES encryption standard. 
 * @version 0.1
 * @date 2019-03-28
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#include "cbc.h"

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
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Start CBC AES Encrypt file\n");
    
    // all ascii** variables used for values that have been converted to ascii. 
    //  conversion only needed if the input is hex. 
    unsigned char* asciiIV; 
    unsigned char* asciiKey; 
    
    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    if(isIvHex) {
        asciiIV = IVHexToAscii(initializationVector,initializationVectorLength);
        initializationVectorLength = initializationVectorLength/2;
    } else {
        asciiIV = initializationVector;
    }

    keyLength = getPaddedKeyLength(keyLength);
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);    
    validateNumRounds(numRounds,keyLength);
    // end check key length 

    //check init vector length, if greater than 16 - cant be done
    // if less than 128 bits so 128/8 chars add zero padding
    if(initializationVectorLength > AES_BLOCK_SIZE) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }
    /* Open file */ 
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
    getOutputFileName(0,fileName,outputFileName, "cbc");
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

    // Copy to padded, memcpy will pad an ASCII 0 for every char missing (Null char) 
    // maximum number of char is 16 since 1 char = 1 byte and 128 bits = 16 bytes
    unsigned char* placeholderBlock = calloc(AES_BLOCK_SIZE,sizeof(char)); // temp cipherText or IV to XOR with plaintext
    memcpy(placeholderBlock,asciiIV,AES_BLOCK_SIZE);  //copy iv to placeholder, add 0 padding if needed for IV

    // initialization vector + key length are fine now, lengths are correct
    // IV is now in placeholderBlock    
    /* Actual CBC Encrypt Start */
    /* Round One */ 
    // read from file and sort out padding
    unsigned char* plainTextBlock; //ascii plainText block 
    size_t readBufferLength; // the amount of bytes read from the file
    
    //  * Process for CBC encrypt file: 
    //  *  Read from file, if hex, convert if not do nothing. Store read converted in plaintextblock
    //  *  Pad the converted plaintextblock and store in paddedPlaintext
    //  * Store IV and previous ciphertext in placeholderblock
    //  * XOR paddedPlaintext and placeholder - store in intermediate
    //  * Encrypt intermediate - store in cipherTextBlock
    //  * Write to the file
    //  * Free memory, read again and check that the read buffer length (amount read from the file iss not 0)
      
    if(isTextHex) {
        unsigned char* tempText = calloc(AES_BLOCK_SIZE*2, sizeof(char));
        readBufferLength = fread(tempText, sizeof(char), AES_BLOCK_SIZE*2, filePointer); // read 32 hex vals at a time
        plainTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        readBufferLength = readBufferLength/2; // half it since it's hex
        hexToAsciiString(tempText,plainTextBlock,readBufferLength*2);
        free(tempText);

    } else { 
        plainTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        readBufferLength = fread(plainTextBlock, sizeof(char), AES_BLOCK_SIZE, filePointer); // read 16 chars at a time - 128 bits
    }

    // Only if the input plaintext is hex:
    // after a read i need to convert to ascii and then after encrypted, convert that to hex before writing
    // when decrypting, after read, convert to ascii, decrypt, convert back to hex
    // padded plain text in case it is less than 16 chars
    unsigned char* paddedPlainText = calloc(AES_BLOCK_SIZE, sizeof(char));
    memcpy(paddedPlainText,plainTextBlock,AES_BLOCK_SIZE); //destination, source
    free(plainTextBlock); 
    plainTextBlock = NULL;
    int numberOfReads = 1; // number of blocks of AES block size or less that has been read from the plaintext file
    if(VERBOSE == 1) {
        printf("Reading block number %d from file\n", numberOfReads); // I read before this
        printf("Plaintext block number %d in HEX format is: \n", numberOfReads); 
        printAESBlock(paddedPlainText);
    }

    unsigned char* intermediate; // result of the XOR between ciphertext/iv and the current plaintext
    unsigned char* cipherTextBlock; //encrypted ciphertext for current block

    while(readBufferLength > 0) {

        // XOR p1 and IV - both of length AES_BLOCK_SIZE
        intermediate = XORBlocks(paddedPlainText, placeholderBlock, AES_BLOCK_SIZE); // need to free
        if(VERBOSE == 1) {
            if(numberOfReads == 1){
                printf("Performing XOR between plaintext block number %d and IV\n", numberOfReads); 
            } else{
                printf("Performing XOR between plaintext block number %d and previous ciphertext\n", numberOfReads);
            }
            printf("Plaintext is: \n");
            printAESBlock(paddedPlainText);
            printf("IV/previous ciphertext is: \n");
            printAESBlock(placeholderBlock);
            printf("Result of XOR is: \n");
            printAESBlock(intermediate);
            printf("Encrypting the XOR result\n\n");            
        }
        // encrypt result
        cipherTextBlock = AESEncrypt(intermediate,paddedKey,AES_BLOCK_SIZE, keyLength);  // need to free unsigned char* plainText, unsigned char* key, int plainTextLength,int keyLength
        if(VERBOSE) {
            printf("CipherText block number %d:\n", numberOfReads);
            printAESBlock(cipherTextBlock);
        }

        free(intermediate); // freed the intermediate memory from xor blocks
        intermediate = NULL; 

        // write only the ascii
        int temp = fwrite(cipherTextBlock,sizeof(char),AES_BLOCK_SIZE, outputFilePointer); // cipherTextblock will always be 16 
        if(VERBOSE == 1) {
            printf("Writing Ciphertext block number %d to file in ASCII format (ASCII encoded)\n", numberOfReads);
        }

        // get ready for next round
        memcpy(placeholderBlock, cipherTextBlock, AES_BLOCK_SIZE*sizeof(char) ); //copy contents of cipherTextBlock - previous cipherText to placeholder block
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
        free(paddedPlainText); // still has previous - need to free for new round
        paddedPlainText = NULL;
        paddedPlainText = calloc(AES_BLOCK_SIZE, sizeof(char));
        memcpy(paddedPlainText,plainTextBlock,AES_BLOCK_SIZE); // padded plain text is the new block's plaintext with 0 padding
        
        free(plainTextBlock); // free initial read from file for the CURRENT round
        plainTextBlock = NULL;
        if(VERBOSE == 1 && readBufferLength > 0) {
            printf("Reading block number %d from file\n", numberOfReads); // read before
            printf("Plaintext block number %d in HEX format is: \n", numberOfReads);
            printAESBlock(paddedPlainText);
        }
    }

    printf("End of CBC AES Encrypt file\n");
    //free memory
    free(paddedKey);
    free(placeholderBlock);
    free(paddedPlainText);
    free(outputFileName);

    // only free ascii** vars if the text is hex, else the caller that past the pointers in will lose their memory
    if(isKeyHex) {
        free(asciiKey);
    }

    if(isIvHex) {
        free(asciiIV); 
    } 

    //close the file to be encrypted
    fclose(filePointer); 
    // close output file 
    fclose(outputFilePointer); 
}

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
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Start CBC AES file Decryption\n");

    unsigned char* asciiIV; 
    unsigned char* asciiKey; 
    
    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    if(isIvHex) {
        asciiIV = IVHexToAscii(initializationVector,initializationVectorLength);
        initializationVectorLength = initializationVectorLength/2;
    } else {
        asciiIV = initializationVector;
    }

    //check init vector length, if greater than 16 - cant be done
    // if less than 128 bits so 128/8 chars add zero padding
    if(initializationVectorLength > AES_BLOCK_SIZE) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
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

    if(VERBOSE == 1) { 
        printf("Input File opened successfully\n");
    }

    FILE *outputFilePointer;
    char* outputFileName = calloc(500,sizeof(char)); 
    getOutputFileName(1,fileName,outputFileName, "cbc"); //decrypt
    
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

    // Copy to padded, memcpy will pad an ASCII 0 for every char missing (Null char) 
    // maximum number of char is 16 since 1 char = 1 byte and 128 bits = 16 bytes
    unsigned char* placeholderBlock = calloc(AES_BLOCK_SIZE,sizeof(char)); // temp cipherText or IV to XOR with plaintext
    memcpy(placeholderBlock,asciiIV,AES_BLOCK_SIZE);  //copy iv to placeholder, add 0 padding if needed for IV

    // initialization vector + key length are fine now, lengths are correct
    // IV is now in placeholderBlock
    
    /* Actual CBC Decrypt Start */
    /* Round One */ 

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
    if(VERBOSE == 1){
        printf("Reading block number %d from file\n", numberOfReads);
        printf("Ciphertext block number %d in HEX format is: \n", numberOfReads);
        printAESBlock(paddedCipherTextBlock);
    }

    unsigned char* intermediate; // result of the XOR between ciphertext/iv and the current plaintext
    unsigned char* plainTextBlock; //encrypted ciphertext for current block
    // /******************/

    while(readBufferLength > 0) {
        
        if(VERBOSE == 1) {
            printf("Decrypting the Ciphertext block number %d\n", numberOfReads);
        }
        // decrypt the ciphertextblockpadded
        intermediate = AESDecrypt(paddedCipherTextBlock,paddedKey,AES_BLOCK_SIZE, keyLength);
        // XOR p1 and IV - both of length AES_BLOCK_SIZE
        plainTextBlock = XORBlocks(intermediate, placeholderBlock, AES_BLOCK_SIZE); // need to free    
        if(VERBOSE == 1) {
            printf("Performing XOR between decrypted Ciphertext and IV/previous Ciphertext\n"); 
            printf("Previous Ciphertext is: \n");
            printAESBlock(placeholderBlock);
            printf("Result of XOR (plaintext number %d) is:\n", numberOfReads);
            printAESBlock(plainTextBlock);
        }
        free(intermediate); // freed the intermediate memory from decrypt blocks
        intermediate = NULL; // set to null
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
            
            fwrite(plainTextBlock,sizeof(char),bytesToWrite, outputFilePointer); // plainTextBlock will always be 16 bytes    
        } // end of isTexHex if statement
        
        free(plainTextBlock); // free XOR blocks
        // get ready for next round
        memcpy(placeholderBlock, paddedCipherTextBlock, AES_BLOCK_SIZE*sizeof(char) ); //copy contents of cipherTextBlock - previous cipherText to placeholder block
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
    free(placeholderBlock);
    free(paddedCipherTextBlock);
    free(outputFileName);

    if(isKeyHex) {
        free(asciiKey);
    }

    if(isIvHex) {
        free(asciiIV); 
    } 
    //close the file to be encrypted
    fclose(filePointer); 
    // close output file 
    fclose(outputFilePointer); 
    printf("End of CBC AES file Decryption\n");
}

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
                    int plainTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Start CBC AES Encryption\n");
    
    // all ascii** variables used for values that have been converted to ascii. 
    //  conversion only needed if the input is hex. 
    unsigned char* asciiIV; 
    unsigned char* asciiKey; 
    unsigned char* asciiPlainText; 
    
    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    if(isIvHex) {
        asciiIV = IVHexToAscii(initializationVector,initializationVectorLength);
        initializationVectorLength = initializationVectorLength/2;
    } else {
        asciiIV = initializationVector;
    }

    if(isTextHex == 1) {        
        plainTextLength = plainTextLength/2;
        unsigned char* tempText = calloc(plainTextLength,sizeof(char));
        // convert to ascii store in temp text
        hexToAsciiString(plainText,tempText,plainTextLength*2);
        asciiPlainText = tempText;
    } else {
        asciiPlainText = plainText; 
    }

    keyLength = getPaddedKeyLength(keyLength); // from AES.h
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    
    validateNumRounds(numRounds,keyLength);
    // end check key length 

    //check init vector length, if greater than 16 - cant be done
    // if less than 128 bits so 128/8 chars add zero padding
    if(initializationVectorLength > AES_BLOCK_SIZE) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }
   
    unsigned char* paddedKey = calloc((keyLength) ,sizeof(char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,asciiKey,keyLength);  

    // Copy to padded, memcpy will pad an ASCII 0 for every char missing (Null char) 
    // maximum number of char is 16 since 1 char = 1 byte and 128 bits = 16 bytes
    unsigned char* placeholderBlock = calloc(AES_BLOCK_SIZE,sizeof(char)); // temp cipherText or IV to XOR with plaintext
    memcpy(placeholderBlock,asciiIV,AES_BLOCK_SIZE);  //copy iv to placeholder, add 0 padding if needed for IV

    // initialization vector + key length are fine now, lengths are correct
    // IV is now in placeholderBlock
    
    /* Actual CBC Encrypt Start */
    /* Round One */ 

    // read from file and sort out padding
    unsigned char* plainTextBlock; //ascii plainText block 
    
    /**
     * Process for CBC encrypt file: 
     *  Read from file, if hex, convert if not do nothing. Store read converted in plaintextblock
     *  Pad the converted plaintextblock and store in paddedPlaintext
     * Store IV and previous ciphertext in placeholderblock
     * XOR paddedPlaintext and placeholder - store in intermediate
     * Encrypt intermediate - store in cipherTextBlock
     * Write to the file
     * Free memory, read again and check that the read buffer length (amount read from the file iss not 0)
     */    
    unsigned char* intermediate; // result of the XOR between ciphertext/iv and the current plaintext
    unsigned char* cipherTextBlock; //encrypted ciphertext for current block
    
    unsigned int blockNum = 1;
    unsigned int blockCounter = 0; 
    
    while(1) {       

        unsigned char* tempPlainText = calloc(AES_BLOCK_SIZE, sizeof(char));        
        int x = 0; 

        for(; x<AES_BLOCK_SIZE;x++) {
            if(blockCounter >= plainTextLength)
                break;
            tempPlainText[x] = asciiPlainText[blockCounter++];
        }
        // XOR p1 and IV - both of length AES_BLOCK_SIZE
        intermediate = XORBlocks(tempPlainText, placeholderBlock, AES_BLOCK_SIZE); // need to free       
        // encrypt result
        if(VERBOSE == 1) {
            printf("Performing XOR between plaintext block number %d and previous ciphertext\n", blockNum);
            printf("Result of XOR is: \n");
            printAESBlock(intermediate);
            printf("Encrypting the XOR result\n\n");            
        }

        cipherTextBlock = AESEncrypt(intermediate,paddedKey,AES_BLOCK_SIZE, keyLength);  // need to free unsigned char* plainText, unsigned char* key, int plainTextLength,int keyLength
        
        printf("CipherText block number %d:\n", blockNum);
        printAESBlock(cipherTextBlock);
        // get ready for next round
        memcpy(placeholderBlock, cipherTextBlock, AES_BLOCK_SIZE*sizeof(char) ); //copy contents of cipherTextBlock - previous cipherText to placeholder block
        free(cipherTextBlock); // free memory for previous cipherText from AES encrypt
        cipherTextBlock = NULL;
        free(intermediate); // freed the intermediate memory from xor blocks
        intermediate = NULL; 
        free(tempPlainText);
        // if all have been read 
        if(blockCounter >= plainTextLength)
            break; 
        
        blockNum++;
    }

    printf("End of CBC AES Encryption\n");
    //free memory
    free(paddedKey);
    free(placeholderBlock);

    // only free ascii** vars if the text is hex, else the caller that past the pointers in will lose their memory
    if(isKeyHex == 1) {
        free(asciiKey);
    }

    if(isIvHex == 1) {
        free(asciiIV); 
    }

    if(isTextHex == 1) {
        free(asciiPlainText);
    }

}

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
                    int cipherTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Start CBC AES Decryption\n");

    unsigned char* asciiIV; 
    unsigned char* asciiKey; 
    unsigned char* asciiCipherText; 
    
    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keyLength);
        keyLength = keyLength/2;
    } else {
        asciiKey = key;
    }

    if(isIvHex) {
        asciiIV = IVHexToAscii(initializationVector,initializationVectorLength);
        initializationVectorLength = initializationVectorLength/2;
    } else {
        asciiIV = initializationVector;
    }

    if(isTextHex == 1) {        
        cipherTextLength = cipherTextLength/2;
        unsigned char* tempText = calloc(cipherTextLength,sizeof(char));
        // convert to ascii store in temp text
        hexToAsciiString(cipherText,tempText,cipherTextLength*2);
        asciiCipherText = tempText;
    } else {
        asciiCipherText = cipherText; 
    }

    //check init vector length, if greater than 16 - cant be done
    // if less than 128 bits so 128/8 chars add zero padding
    if(initializationVectorLength > AES_BLOCK_SIZE) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    keyLength = getPaddedKeyLength(keyLength); // from AES.h
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);
    // end check key length 
    
    unsigned char* paddedKey = calloc((keyLength) ,sizeof(char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,asciiKey,keyLength);  

    // Copy to padded, memcpy will pad an ASCII 0 for every char missing (Null char) 
    // maximum number of char is 16 since 1 char = 1 byte and 128 bits = 16 bytes
    unsigned char* placeholderBlock = calloc(AES_BLOCK_SIZE,sizeof(char)); // temp cipherText or IV to XOR with plaintext
    memcpy(placeholderBlock,asciiIV,AES_BLOCK_SIZE);  //copy iv to placeholder, add 0 padding if needed for IV

    // initialization vector + key length are fine now, lengths are correct
    // IV is now in placeholderBlock
    
    /* Actual CBC Decrypt Start */
    /* Round One */ 
    // read from file and sort out padding
    // now in decrypt, it and is stored as hex, need to read 32, convert to ascii, decrypt, convert back to hex and write
    
    unsigned char* intermediate; // result of the XOR between ciphertext/iv and the current plaintext
    unsigned char* plainTextBlock; //encrypted ciphertext for current block
    unsigned int blockCounter = 0; 
    unsigned int blockNum = 1;

    while(1) {
        
        unsigned char* cipherTextBlock = calloc(AES_BLOCK_SIZE, sizeof(char));
        int x = 0; 
        for(x; x<AES_BLOCK_SIZE; x++){
            if(x >= cipherTextLength)
                break; 
            cipherTextBlock[x] = asciiCipherText[blockCounter++];
        }
        // decrypt the ciphertextblockpadded
         if(VERBOSE == 1) {
            printf("Decrypting the Ciphertext block number %d\n", blockNum);
        }
        intermediate = AESDecrypt(cipherTextBlock,paddedKey,AES_BLOCK_SIZE, keyLength);
        // XOR p1 and IV - both of length AES_BLOCK_SIZE
        plainTextBlock = XORBlocks(intermediate, placeholderBlock, AES_BLOCK_SIZE); // need to free    
        
        printf("Plaintext block number %d:\n", blockNum);
        printAESBlock(plainTextBlock);

        free(intermediate); // freed the intermediate memory from decrypt blocks
        intermediate = NULL; // set to null

        free(plainTextBlock); // free XOR blocks
        // get ready for next round
        memcpy(placeholderBlock, cipherTextBlock, AES_BLOCK_SIZE*sizeof(char) ); //copy contents of cipherTextBlock - previous cipherText to placeholder block
        free(cipherTextBlock); // free memory for previous cipherText from AES encrypt
        cipherTextBlock = NULL; 
        
        if(blockCounter >= cipherTextLength)
            break;
        blockNum++;
    }
    //free memory
    free(paddedKey);
    free(placeholderBlock);

    if(isKeyHex) {
        free(asciiKey);
    }

    if(isIvHex) {
        free(asciiIV); 
    } 
    
    if(isTextHex == 1) {
        free(asciiCipherText);
    }
    printf("End of CBC AES Decryption\n");
}


