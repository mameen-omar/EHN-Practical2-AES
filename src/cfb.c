// Mohamed Ameen Omar (u16055323)
/**
 * @file cfb.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Cipher Feedback (CFB) - AES implementation file
 * This file contains the implementation of the functions used for the CFB mode of AES encryption. 
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

#include "cfb.h"

/**
 * @brief Variable - size_t const shiftRegLength - used to specify the length of the shift register.
 */
size_t const shiftRegLength = 16; // 16 bytes
/**
 * @brief Variable - size_t const streamSize - used to speciffy the length of the stream per encryption round.
 */
size_t const streamSize = 16; // 16 bytes 

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
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Begin CFB AES Encrypt file\n");

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
    if(initializationVectorLength > shiftRegLength) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    keyLength = getPaddedKeyLength(keyLength); // from AES.h
    printf("Padded key length is %d\n\n", keyLength);
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
    getOutputFileName(0,fileName,outputFileName, "cfb"); //encrypt
    
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

    unsigned char* shiftRegister = calloc(shiftRegLength,sizeof(char));
    //sort out shift register
    //encrypt IV 
    if(VERBOSE) {
        printf("Encrypting the IV\n"); 
    }

    unsigned char* encryptedIV = AESEncrypt(asciiIV,paddedKey,initializationVectorLength,keyLength);
    memcpy(shiftRegister,encryptedIV,shiftRegLength);
    size_t readBufferLength = 0;
    unsigned char* plainTextBlock; 
    unsigned char* cipherTextBlock; 

    do {
        readBufferLength = 0;
        // Reading the 16 chars at a time
       
        if(isTextHex) {
            unsigned char* tempText = calloc(streamSize*2, sizeof(char));
            readBufferLength = fread(tempText, sizeof(char), streamSize*2, filePointer); // read streamsize*2 hex vals at a time
            plainTextBlock = calloc(streamSize, sizeof(char));
            readBufferLength = readBufferLength/2;
            hexToAsciiString(tempText,plainTextBlock,readBufferLength*2);
            free(tempText);
        } else { 
            plainTextBlock = calloc(streamSize, sizeof(char));
            readBufferLength = fread(plainTextBlock, sizeof(char), streamSize, filePointer); // read streamSize chars at a time
        }
        
        if(readBufferLength <= 0) {
            free(plainTextBlock);
            break; 
        }

        if(VERBOSE) {
            printf("Reading plaintext block from file\n");
            printf("Plaintext read is:\n"); 
            for(int x = 0; x<streamSize;x++) {
                printf("%02X\t", plainTextBlock[x]);
            } printf("\n");
        }

        cipherTextBlock = XORBlocks(shiftRegister,plainTextBlock,streamSize);

        if(VERBOSE) {
            printf("XORing the plaintext block and the shift register\n");
            printf("CipherTextBlock is: \n");
            for(int x  = 0; x<streamSize;x++)
                printf("%02X\t", cipherTextBlock[x]);
            printf("\n");
            printf("Writing Ciphertext to file.\n");
        }

        // write cipherText to file
        int temp = fwrite(cipherTextBlock,sizeof(char),streamSize, outputFilePointer); //streamSize
        
        if(VERBOSE) {
            printf("Writing Ciphertext to file\n");
            printf("Encrypting Ciphertext and storing in shift register\n");
        }

        unsigned char* tempReg = AESEncrypt(cipherTextBlock,paddedKey,streamSize,keyLength);
        free(shiftRegister);
        shiftRegister = calloc(shiftRegLength, sizeof(char));
        memcpy(shiftRegister,tempReg,shiftRegLength);
        free(tempReg);
        free(plainTextBlock);
        free(cipherTextBlock);

    } while(readBufferLength > 0);
    // read 8 chars at a time, input into
     
    free(paddedKey);
    free(encryptedIV);
    free(shiftRegister);
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

    printf("End CFB AES Encrypt file\n");
}

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
                    int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Begin CFB AES Decrypt File\n");
    
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
    if(initializationVectorLength > shiftRegLength) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    keyLength = getPaddedKeyLength(keyLength); // from AES.h
    printf("Padded key length is %d\n\n", keyLength);
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
    getOutputFileName(1,fileName,outputFileName, "cfb"); //decrypt
    
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
    printAESBlock(paddedKey);
    unsigned char* shiftRegister = calloc(shiftRegLength,sizeof(char));
    //sort out shift register
    //encrypt IV 
    if(VERBOSE) {
        printf("Encrypting the IV\n"); 
    }
    unsigned char* encryptedIV = AESEncrypt(asciiIV,paddedKey,initializationVectorLength,keyLength);
    memcpy(shiftRegister,encryptedIV,shiftRegLength);
    size_t readBufferLength = 0;
    unsigned char* plainTextBlock; 
    unsigned char* cipherTextBlock; 
    do {
        // Reading the 16 chars at a time
       
        if(isTextHex) {
            unsigned char* tempText = calloc(streamSize*2, sizeof(char));
            readBufferLength = fread(tempText, sizeof(char), streamSize*2, filePointer); // read streamsize*2 hex vals at a time
            cipherTextBlock = calloc(streamSize, sizeof(char));
            readBufferLength = readBufferLength/2;
            hexToAsciiString(tempText,cipherTextBlock,readBufferLength*2);
            free(tempText);
        } else { 
            cipherTextBlock = calloc(streamSize, sizeof(char));
            readBufferLength = fread(cipherTextBlock, sizeof(char), streamSize, filePointer); // read streamSize chars at a time
        }

        if(readBufferLength <= 0 ) {
            free(cipherTextBlock);
            break; 
        }

        if(VERBOSE) {
            printf("Reading ciphertext block from file\n");
        }
        
        plainTextBlock = XORBlocks(shiftRegister,cipherTextBlock,streamSize);

        if(VERBOSE) {
            printf("XORing shift register and ciphertext\n"); 
            printf("Plaintext block is: \n");
            for(int x  = 0; x<streamSize;x++) {
                printf("%02X\t", plainTextBlock[x]);
            }
            printf("\n");
        }

        int bytesToWrite = 0;
        if(isTextHex) {
            // convert to hex, write double length
            unsigned char* hexString = calloc(streamSize*2, sizeof(char));
            asciiToHexString(plainTextBlock, hexString, streamSize); 
            fwrite(hexString,sizeof(char),streamSize*2, outputFilePointer);
            free(hexString);
            
        } else {
            // text is not hex and the file is txt, dont write padding  - remove zero padding
            if(isFileTxt(fileName) == 1) {
                    // check for zero padding
                for(; bytesToWrite < streamSize; bytesToWrite++) {
                    if(plainTextBlock[bytesToWrite] == 0x00)
                        break;
                }            
            } else {
                bytesToWrite = streamSize; // we write the whole block if not txt
            }            
            fwrite(plainTextBlock,sizeof(char),bytesToWrite, outputFilePointer); // plainTextBlock will always be 16 bytes    
        } // end of isTexHex if statement

        if(VERBOSE) {
            printf("Writing plaintext to file\n");
            printf("Encrypting Ciphertext and storing in shift register\n");
        }

        unsigned char* tempReg = AESEncrypt(cipherTextBlock,paddedKey, shiftRegLength,keyLength);
        free(shiftRegister);
        shiftRegister = calloc(shiftRegLength, sizeof(char));
        memcpy(shiftRegister,tempReg,shiftRegLength);
        free(tempReg);
        free(plainTextBlock);
        free(cipherTextBlock);

    } while(readBufferLength > 0);
    // read 8 chars at a time, input into
     
    free(paddedKey);
    free(encryptedIV);
    free(shiftRegister);
    free(outputFileName);

    if (isKeyHex) {
        free(asciiKey);
    }

    if (isIvHex) {
        free(asciiIV); 
    } 
    //close the file to be encrypted
    fclose(filePointer); 
    // close output file 
    fclose(outputFilePointer); 
    printf("End CFB Decrypt File\n");
}

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
                int plainTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{

    printf("Start of CFB AES Encryption\n");
    
    unsigned char* asciiIV; 
    unsigned char* asciiKey; 
    unsigned char* asciiPlainText; 

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

    if(isIvHex) {
        asciiIV = IVHexToAscii(initializationVector,initializationVectorLength);
        initializationVectorLength = initializationVectorLength/2;
    } else {
        asciiIV = initializationVector;
    }

    //check init vector length, if greater than 16 - cant be done
    // if less than 128 bits so 128/8 chars add zero padding
    if(initializationVectorLength > shiftRegLength) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    keyLength = getPaddedKeyLength(keyLength); 
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);
    // end check key length 
    
    unsigned char* paddedKey = calloc((keyLength) ,sizeof(char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,asciiKey,keyLength);  

    unsigned char* shiftRegister = calloc(shiftRegLength,sizeof(char));
    //sort out shift register
    //encrypt IV 
    if(VERBOSE) {
        printf("Encrypting the IV\n"); 
    }
    unsigned char* encryptedIV = AESEncrypt(asciiIV,paddedKey,initializationVectorLength,keyLength);
    memcpy(shiftRegister,encryptedIV,shiftRegLength);

    int blockCounter = 0; 
    int blockNum = 1;

    unsigned char* plainTextBlock; 
    unsigned char* cipherTextBlock; 

    while(1) {

        unsigned char* plainTextBlock = calloc(streamSize, sizeof(char)); 

        int x = 0; 
        // copy the next plaintext block 
        for(; x<streamSize;x++) {
            if(blockCounter >= plainTextLength)
                break;
            plainTextBlock[x] = asciiPlainText[blockCounter++];
        }

        unsigned char* placeholder = calloc(streamSize,sizeof(char)); // temp storage for the shift register
        for(int x = 0; x < streamSize;x++) {
            placeholder[x] = shiftRegister[x];
        }
        if(VERBOSE) {
            printf("XORing the plaintext block and the shift register\n");
        }
        cipherTextBlock = XORBlocks(placeholder,plainTextBlock,streamSize);
        /*****************************/
        printf("CipherTextBlock is: \n");
        for(int x  = 0; x<streamSize;x++) {
            printf("%02X\t", cipherTextBlock[x]);
        }
        printf("\n");
        /*****************************/
        if(VERBOSE) {
            printf("Encrypting Ciphertext and storing in shift register\n");
        }
        unsigned char* tempReg = AESEncrypt(cipherTextBlock,paddedKey, shiftRegLength,keyLength);
        free(shiftRegister);
        shiftRegister = calloc(shiftRegLength, sizeof(char));
        memcpy(shiftRegister,tempReg,shiftRegLength);
        free(tempReg);

        free(plainTextBlock);
        free(placeholder); 
        free(cipherTextBlock);
        if(blockCounter >= plainTextLength)
            break; 
                
        blockNum++;
    } 
     
    free(paddedKey);
    free(encryptedIV);
    free(shiftRegister);
    if(isKeyHex) {
        free(asciiKey);
    }

    if(isIvHex) {
        free(asciiIV); 
    } 

    if(isTextHex == 1) {
        free(asciiPlainText);
    }

    printf("End of CFB AES Encryption\n");
}


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
                int cipherTextLength, int keyLength, int initializationVectorLength, int isTextHex, int isKeyHex, int isIvHex)
{
    printf("Start of CFB AES Decryption\n");

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
    if(initializationVectorLength > shiftRegLength) {
        printf("Error the initializationVectorLength is not valid, entered a block with length = %d characters\n", initializationVectorLength); 
        printf("Program will now exit\n");
        exit(EXIT_FAILURE);
    }

    keyLength = getPaddedKeyLength(keyLength);
    // check key length, if not valid, end program
    int numRounds = getNumRounds(keyLength);
    validateNumRounds(numRounds,keyLength);
    // end check key length 
    
    unsigned char* paddedKey = calloc(keyLength, sizeof(char));
    // will pad zeroes of the new key length is greater than the older key length
    memcpy(paddedKey,asciiKey,keyLength); 

    unsigned char* shiftRegister = calloc(shiftRegLength,sizeof(char));
    //sort out shift register
    //encrypt IV 
    if(VERBOSE) {
        printf("Encrypting the IV\n"); 
    }
    unsigned char* encryptedIV = AESEncrypt(asciiIV,paddedKey,initializationVectorLength,keyLength);
    memcpy(shiftRegister,encryptedIV,shiftRegLength);

    unsigned char* plainTextBlock; 
    unsigned char* cipherTextBlock; 
    unsigned int blockCounter = 0; 
    unsigned int blockNum = 1;
    
    while(1) {
        unsigned char* cipherTextBlock = calloc(streamSize, sizeof(char));
        int x = 0; 
        // Read ciphertext block of length "stream size" to be decrypted
        for(x; x<streamSize; x++) {
            if(x >= cipherTextLength)
                break; 
            cipherTextBlock[x] = asciiCipherText[blockCounter++];
        }

        unsigned char* placeholder = calloc(streamSize,sizeof(char));
        for(int x = 0; x < streamSize;x++) {
            placeholder[x] = shiftRegister[x];
        }
        if(VERBOSE) {
            printf("XORing shift register and ciphertext\n"); 
        }
        plainTextBlock = XORBlocks(placeholder,cipherTextBlock,streamSize);

        printf("\nPlaintext block %d is: \n", blockNum);

        for(int x  = 0; x<streamSize;x++) {
            printf("%02X\t", plainTextBlock[x]);
        }
        printf("\n");

        if(VERBOSE) {
            printf("Encrypting Ciphertext and storing in shift register\n");
        }

        unsigned char* tempReg = AESEncrypt(cipherTextBlock,paddedKey, shiftRegLength,keyLength);
        free(shiftRegister);
        shiftRegister = calloc(shiftRegLength, sizeof(char));
        memcpy(shiftRegister,tempReg,shiftRegLength);
        free(tempReg);
        free(plainTextBlock);
        free(placeholder); 
        free(cipherTextBlock);
        if(blockCounter >= cipherTextLength)
            break;
        blockNum++;
    }
     
    free(paddedKey);
    free(encryptedIV);
    free(shiftRegister);

    if(isKeyHex) {
        free(asciiKey);
    }

    if(isIvHex) {
        free(asciiIV); 
    } 

    if(isTextHex == 1) {
        free(asciiCipherText);
    }

    printf("End of CFB AES Decryption\n");
}

