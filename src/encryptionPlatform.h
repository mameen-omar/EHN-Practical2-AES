#ifndef ENCRYPTION_PLATFORM_H
#define ENCRYPTION_PLATFORM_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h> 
#include <unistd.h>
#include <getopt.h>
#include "AES.h"
#include "cfb.h"
#include "cbc.h"
#include "ecb.h"

extern size_t VERBOSE; // for verbose output 
extern const size_t AES_BLOCK_SIZE; // number of blocks in BYTES

/**
 * @brief Prints a usage menu to be shown to a user when entering the 'help' command line parameter or when parameters are entered incorrectly.
 * @return
 */
void printHelp(); 

/**
 * @brief Free up memory allocated to stored key and IV
 * 
 * @param char Pointer to a location in memory containing the key
 * @param char Pointer to a location in memory containing the IV
 * @param freeKey Boolean value indicating whether or not the IV memory should be freed
 * @param freeIV Boolean value indicating whether or not the Key memory should be freed
 */
void freeMemory(unsigned char* key, unsigned char* IV, int freeKey, int freeIV); 

#endif