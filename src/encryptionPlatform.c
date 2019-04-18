/**
 * @file encryptionPlatform.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708) 
 * @brief Implementation file for the cbc and cfb encryption platform.
 * All functions, to specify key, IV, type of encrytion mode, file path or string controlled by commandline parameters.
 * @version 0.1
 * @date 2019-04-03
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#include "encryptionPlatform.h"

int main(int argc, char* argv[])
{
    if(argc <= 1) {
        printHelp();
        exit(EXIT_FAILURE);
    }

    VERBOSE = 0; // Default to brief output
    unsigned char* fileName = NULL;
    unsigned char* key = NULL; 
    unsigned char* IV = NULL; 
    unsigned char* mode = "ecb";
    unsigned char* plaintext = NULL; // default null chars
    unsigned char* ciphertext = NULL; // default null chars
    uint8_t isTextHex = 0; // default to not hex 
    uint8_t isKeyHex = 0; // default to not hex
    uint8_t isIVHex = 0; // default to not hex

    int opt = 0;
    // used to check encrypt (0) or decrypt (1)
    int operationFlag = 0;  //default to encrypt 

    // Struct containing all possible command-line parameters that can be passed into execution at run-time
    static struct option long_options[] = {
        {"filename",    required_argument,   0,  'f' },
        {"key",         required_argument,       0,  'k' },
        {"IV",          required_argument, 0,  'i' },
        {"plaintext",     required_argument, 0,  'p' },
        {"ciphertext",     required_argument, 0,  'c' },
        {"mode",     required_argument, 0,  'm' },
        {"verbose",     no_argument, 0,  'v' },
        {"hextext",     no_argument, 0,  'T' },
        {"hexiv",     no_argument, 0,  'I' },
        {"hexkey",     no_argument, 0,  'K' },
        {"help",     no_argument, 0,  'h' },
        {"encrypt",     no_argument, 0,  'e' },
        {"decrypt",     no_argument, 0,  'd' },
        {0,           0,                 0,  0   } // always required
    };

    int long_index = 0;

    while ((opt = getopt_long(argc, argv,"edhf:k:i:p:c:m:vTI:K:F:P:C:", long_options, &long_index )) != -1) {
        switch (opt) {
            // filename
            case 'F': isTextHex = 1;
            case 'f': fileName = optarg;
                break;
            // key
            case 'K': isKeyHex = 1;
            case 'k': key = optarg;
                break;
            // initialization vector
            case 'I': isIVHex = 1;
            case 'i': IV = optarg;
                break;
            // plaintext
            case 'P': isTextHex = 1;
            case 'p': plaintext = optarg; 
                break;

            // ciphertext 
            case 'C': isTextHex = 1;
            case 'c': ciphertext = optarg;
                break;
            // mode 
            case 'm': mode = optarg;
                break;
            // verbose
            case 'v': VERBOSE = 1;
                break;
            // text plain or cipher is hex
            case 'T': isTextHex = 1;
                break;
            
            case 'd': operationFlag = 1; 
                break;

            case 'e': operationFlag = 0;  
                break;

            case 'h':
            case '?':
                printHelp();
                exit(EXIT_FAILURE);
                break;

            default: printHelp();
                exit(EXIT_FAILURE); 
                    
        }
    }

    int freeKey = 0; // flag to see if we must free the key or not
    int freeIV = 0; // flag to see if we must free IV

    printf("Begin encryption platform\n");
    if(key == NULL) {
        printf("No key specified, defaulting to a null 128 bit key\n");
        key = calloc(16,sizeof(char)); // default to null key
        freeKey = 1;
        isKeyHex = 0; //not hex
    }

    if(IV == NULL) {
        printf("No IV specified, defaulting to a null 128 bit IV\n");
        IV = calloc(16,sizeof(char)); // default to null IV
        freeIV = 1;
        isIVHex = 0; 
    }

    if(fileName != NULL) {
        printf("Specified file name: %s\n", fileName);
    }

    if(operationFlag == 1) {
        // decrypt
        if(fileName == NULL && ciphertext == NULL) {
            printf("Error no filename or ciphertext specified\n");
            printHelp();
            freeMemory(key,IV,freeKey,freeIV); 
            exit(EXIT_FAILURE);
        }
        
        if(strcmp(mode,"ecb") == 0) {
            printf("ECB Decrypt has been specified\n"); 
            if(fileName != NULL) {
                printf("Decrypting file: %s\n", fileName);
                ecbDecryptFile(fileName,key,strlen(key), isTextHex,isKeyHex);
            } else {
                printf("Decrypting user input %s\n", ciphertext);
                ecbDecrypt(ciphertext,key, strlen(ciphertext),strlen(key),isTextHex,isKeyHex);
            }

        } else if(strcmp(mode,"cbc") == 0) {
            printf("CBC Decrypt has been specified\n");
            if(fileName != NULL) {
                printf("Decrypting file: %s\n", fileName);
                cbcDecryptFile(fileName,key,IV,strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            } else {
                printf("Decrypting user input\n");                
                cbcDecrypt(ciphertext,key,IV,strlen(ciphertext),strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            }
        } else if(strcmp(mode,"cfb") == 0) {
            printf("CFB decrypt has been specified\n");
            if(fileName != NULL) {
                printf("Decrypting file: %s\n", fileName);
                cfbDecryptFile(fileName,key,IV,strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            } else {
                printf("Decrypting user input\n");
                cfbDecrypt(ciphertext,key,IV,strlen(ciphertext),strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            }
        } else {
            printf("Error mode %s, is not valid\n", mode);
            printHelp();
            freeMemory(key,IV,freeKey,freeIV); 
            exit(EXIT_FAILURE); 
        }


    } else { // default is encrypt
        //encrypt
        if(fileName == NULL && plaintext == NULL) {
            printf("Error no filename or plaintext specified\n");
            printHelp();
            freeMemory(key,IV,freeKey,freeIV); 
            exit(EXIT_FAILURE);
        }
        
        if (strcmp(mode,"ecb") == 0) {
            printf("ECB Encrypt has been specified\n"); 
            if(fileName != NULL) {
                printf("Encrypting file: %s\n", fileName);
                ecbEncryptFile(fileName,key,strlen(key), isTextHex,isKeyHex);
            } else {
                printf("Encrypting user input %s\n", plaintext);
                ecbEncrypt(plaintext,key, strlen(plaintext),strlen(key),isTextHex,isKeyHex);
            }

        } else if(strcmp(mode,"cbc") == 0) {
            printf("CBC Encrypt has been specified\n");
            if(fileName != NULL) {
                printf("Encrypting file: %s\n", fileName);
                cbcEncryptFile(fileName,key,IV,strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            } else {
                printf("Encrypting user input\n");
                cbcEncrypt(plaintext,key,IV,strlen(plaintext),strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            }
        } else if(strcmp(mode,"cfb") == 0) {
            printf("CFB Encrypt has been specified\n");
            
            if(fileName != NULL) {
                printf("Encrypting file: %s\n", fileName);
                cfbEncryptFile(fileName,key,IV,strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            } else {
                printf("Encrypting user input\n");   
                cfbEncrypt(plaintext,key,IV,strlen(plaintext),strlen(key),strlen(IV),isTextHex,isKeyHex,isIVHex);
            }
        } else {
            printf("Error mode %s, is not valid\n", mode);
            printHelp();
            freeMemory(key,IV,freeKey,freeIV); 
            exit(EXIT_FAILURE); 
        }
    } // end of else encrypt   

    freeMemory(key,IV,freeKey,freeIV); 
    printf("End encryption platform\n");
    return 0;
}

/**
 * @brief Prints a usage menu to be shown to a user when entering the 'help' command line parameter or when parameters are entered incorrectly.
 * @return
 */
void printHelp()
{
    printf("An encryption platform supporting AES ecb, cbc and cfb encryption and decryption\n");
	printf("\nUsage ./encryptionPlatform <optional paramters> <optional arguments> \nIf no arguments are specified the default parameter values are used.\n\n");
	printf("-h or --help       \t \t Prints out the help menu \n");
    printf("-f or --filename   \t \t Specifies the filename                                         \t Default: None\n");
    printf("-F                 \t \t Specifies the path to a hex file                               \t Default: None\n");
    printf("-k or --key        \t \t Specifies the key                                              \t Default: 128 bit NULL key\n");
    printf("-K                 \t \t Specifies the key (in hex)                                     \t Default: None\n");
    printf("-i or --IV         \t \t Specifies the Initialization vector                            \t Default: 128 bit NULL IV\n");
    printf("-I                 \t \t Specifies the Initialization vector (in hex)                   \t Default: None\n");
    printf("-p or --plaintext  \t \t Specifies the plaintext to encrypt                             \t Default: None\n");
    printf("-P                 \t \t Specifies the plaintext to encrypt (in hex)                    \t Default: None\n");
    printf("-c or --ciphertext \t \t Specifies the ciphertext to decrypt                            \t Default: None\n");
    printf("-C                 \t \t Specifies the ciphertext to decrypt (in hex)                   \t Default: None\n");
    printf("-m or --mode       \t \t Specifies the mode of encryption or decryption (ecb,cbc or cfb)\t Default: ecb\n");
    printf("-v or --verbose    \t \t Specifies to print verbose output                              \t Default: Brief output\n");
    printf("-e or --encrypt    \t \t Specifies to encrypt the input                                 \t Default: Encrypt input\n");
    printf("-d or --decrypt    \t \t Specifies to decrypt the input                                 \t Default: Encrypt input\n");    
    printf("-T or --hextext    \t \t Specifies that the input text is a hex string (No args needed) \t Default: ASCII input\n");
}

/**
 * @brief Free up memory allocated to stored key and IV
 * 
 * @param char Pointer to a location in memory containing the key
 * @param char Pointer to a location in memory containing the IV
 * @param freeKey Boolean value indicating whether or not the IV memory should be freed
 * @param freeIV Boolean value indicating whether or not the Key memory should be freed
 */
void freeMemory(unsigned char* key, unsigned char* IV, int freeKey, int freeIV)
{
    if(freeKey == 1) {
        free(key);
    }
    if(freeIV == 1) {
        free(IV); 
    }
}


