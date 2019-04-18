#Makefile 
TARGET = main
DEBUG = debug

CC = gcc -O3
CFLAGS = -lm #-Wall -lcrypto -Wextra
DEBUG_FLAG = DEBUG

encryptionPlatform: aes cbc cfb ecb
	$(CC) -c -g $(CFLAGS) encryptionPlatform.c
	$(CC) -g -o encryptionPlatform encryptionPlatform.o AES.o cfb.o cbc.o ecb.o


aes: 
	$(CC) -c -g $(CFLAGS) AES.c

main: aes
	$(CC) -c -g $(CFLAGS) main.c 
	$(CC) -g -o main main.o AES.o

run-main: clean main
	./main

clean:
	rm -f *.o *.exe *.out main myTester encryptionPlatform aesTester cbcTester cfbTester ecbTester

tester: clean
	$(CC) -c -g $(CFLAGS) myTester.c 
	$(CC) -g -o myTester myTester.o

aesTester: aes 
	$(CC) -c -g $(CFLAGS) aesTester.c 
	$(CC) -g -o aesTester aesTester.o AES.o 

cbc:
	$(CC) -c -g $(CFLAGS) cbc.c

cfb:
	$(CC) -c -g $(CFLAGS) cfb.c
ecb: 
	$(CC) -c -g $(CFLAGS) ecb.c

cbcTester: aes cbc
	$(CC) -c -g $(CFLAGS) cbcTester.c 
	$(CC) -g -o cbcTester cbcTester.o AES.o cbc.o -lm

ecbTester: aes ecb
	$(CC) -c -g $(CFLAGS) ecbTester.c 
	$(CC) -g -o ecbTester ecbTester.o AES.o ecb.o -lm

cfbTester: aes cfb
	$(CC) -c -g $(CFLAGS) cfbTester.c 
	$(CC) -g -o cfbTester cfbTester.o AES.o cfb.o 

run-cfbTester: clean cfbTester
	./cfbTester

run-ecbTester: clean ecbTester
	./ecbTester

run-cbcTester: clean cbcTester
	./cbcTester

run-aesTester: clean aesTester
	./aesTester

run-tester: clean tester
	./myTester

run-encryptionPlatform: clean encryptionPlatform
	./encryptionPlatform