************************************
# EHN 410 - Group 7
************************************

************************************
## Group members:
************************************
* Mohamed Ameen Omar (u16055323)
* Douglas Healy (u16018100)
* Llewellyn Moyse (u15100708)

************************************
## To run Encryption Platform
************************************
1. Open a Linux Terminal.
2. Navigate to the Encyption Platform Directory.
3. Run the "make" command.
4. An executable called "encyptionPlatform" will be created. 
5. Use "./encyptionPlatform" to run the encryption platform. (if no input parameters are specified, a help menu will be displayed)
6. A list of input parameter and default values:

| Parameter          	| Description                                     	| Default Value    	|
|--------------------	|-------------------------------------------------	|------------------	|
| -h                 	| Print out the help menu                         	|                  	|
| -f or --filename   	| Path to an ASCII file to encrypt/decrypt        	| None             	|
| -F                 	| Path to a hex file to encrypt/decrypt           	| None             	|
| -k or --key        	| The encryption key                              	| 128 bit NULL key 	|
| -K                 	| The encryption key (in hex)                     	| None             	|
| -i or --IV         	| The Initialisation vector                       	| 128 bit NULL IV  	|
| -I                 	| The Initialisation vector (in hex)              	| None             	|
| -p or --plaintext  	| Plaintext to encrypt                            	| None             	|
| -P                 	| Plaintext to encrypt (in hex)                   	| None             	|
| -c or --ciphertext 	| Ciphertext to decrypt                           	| None             	|
| -C                 	| Ciphertext to decrypt (in hex)                  	| None             	|
| -m or --mode       	| Mode of encryption/decryption (ecb, cbc or cfb) 	| ecb              	|
| -v or --verbose    	| Print verbose output                            	| Flag not set     	|
| -e or --encrypt    	| Encrypt plaintext or file                       	| Flag set         	|
| -d or --decrypt    	| Decrypt ciphertext or file                      	| Flag not set     	|
| -T                 	| Set if input text is a hex string               	| Flag not set     	|
			
## File Encryption Example
```
./encryptionPlatform -e -f <path/unencrypted_file.ext> -k <key> -i <iv>
./encryptionPlatform -e -F <path/unencrypted_hex_file.ext> -K <hex_key> -I <hex_iv>
```

## File Encryption Example
```
./encryptionPlatform -d -f <path/encrypted_file.ext> -k <key> -i <iv>
./encryptionPlatform -d -F <path/encrypted_hex_file.ext> -F <hex_key> -I <hex_iv>
```
