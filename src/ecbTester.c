#include "ecb.h" 

// Testing with https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

int main(int argc, char * argv[])
{
    // unsigned char* hexPlainText = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    // int hexPlainTextLength = strlen(hexPlainText); 
    // unsigned char* Key128 = "2b7e151628aed2a6abf7158809cf4f3c";
    // ecbEncrypt(hexPlainText,Key128, hexPlainTextLength, strlen(Key128),1,1);
    // unsigned char* hexCipherText =  "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4";
    // int hexCipherTextLength = strlen(hexCipherText);
    // ecbDecrypt(hexCipherText,Key128, hexCipherTextLength, strlen(Key128),1,1);

    //char* fileName = "./testFiles/hello.png";
    char* fileNameD = "yeet.txt";
    unsigned char* key = "274590430EAA3952504E4E4363C9361BCA87CAD38FB64CC0204642B2A4AE9622"; //"2b7e151628aed2a6abf7158809cf4f3c";
    //unsigned char* IV = "4c6a606a90bd84c0402ee2a81783d6e8"; //"000102030405060708090a0b0c0d0e0f"; 
    //char* temp = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    //ecbEncryptFile(fileName, key,strlen(key),0,1); // all hex
    
    ecbDecryptFile(fileNameD, key,strlen(key),0,1);

   


    return 0; 
}