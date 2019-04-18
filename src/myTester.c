#include "stdio.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int main()
{   
    FILE *fp = fopen("./testFiles/hello.png", "rb");
    if(fp == NULL){
        printf("FUCKED");
    }
    FILE *fpW = fopen("./testFiles/writeHello.png","wb");
    unsigned char * temp = calloc(sizeof(char), 16);
    int read = fread(temp, sizeof(char), 16, fp); 
    printf("%d", read);
    while(read != 0){
        printf("HERE");
        fwrite(temp,sizeof(char),read,fpW); 
        free(temp); 
        temp = calloc(sizeof(char),16);
        read = fread(temp, sizeof(char), 16, fp); 

    }


    return 0;
}