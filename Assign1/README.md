## Crypto Algorithms

A crypto library implementing 3 cryptographic algorithms: One-Time-Pad, Caesar's cipher, Vigenère's cipher.

### Steps to Reproduce
Compile and run the program: make
Run the program: make run or ./demo

### OTP

##### Description
The one-time-pad is fully secure given that the key for encryption/decryption is only used once. The size of the key must be the same or longer than the plaintext.

* OTP Encryption: each byte of the plaintext is XORed with the key to get the ciphertext.
* OTP Decryption: each byte of the ciphertext is XORed with the key to get the 
original plaintext.

##### Implementation
Both the encryption and decryption are utilized in the function below. The enc_dec parameter is 1 for encryption and 0 for decryption.

``` c
unsigned char* otp_crypto(unsigned char *msg, unsigned char *key, bool enc_dec)
```
* **Encryption**
    1. A key is generated in a different function ```generateKey()``` which uses the /dev/urandom pseudorandom generator of unix.
    2. The plaintext is converted from character array to hex values, to have the same representation as the key because the /dev/urandom returns bytes.
    3. Each byte of the plaintext is XORed with the corresponding byte of the key and produce the ciphertext.

* **Decryption**
	1. As the key and ciphertext are in hex, their bytes are XORed and produce the plaintext in hex.
	2. A helper function ```hexToChar()``` converts the hex array to characters to produce the original plaintext.



### Caesar's cipher


##### Description
The caesar's cipher is one of the oldest symmetric key crypto techniques and it is easy to implement.


##### Implementation
Both the encryption and decryption are utilized in the functions below. The enc_dec parameter is 1 for encryption and 0 for decryption. 

``` c
unsigned char* caesars_crypto(unsigned char* msg, int key, bool enc_dec)
```
``` c
char findCaesarChar(char c, char* alphabet, int key, bool enc_dec)
```
* **Encryption**
    1. The alphabet set is generated in the function ```setAlphabet()```.
    The alphabet set used is the [0-9A-Za-z]
    2. Each character on the plaintext is substituted with the character shifted *key* positions to the right on the alphabet set.

* **Decryption**
    1. The alphabet set is generated in the function ```setAlphabet()```.
    The alphabet set used is the [0-9A-Za-z]
	2. The reverse operation is followed where each character on the ciphertext is substituted with the character shifted *key* positions to the left on the alphabet set. 


### Vigenère's cipher

##### Description
Vigenere's cipher is a polyalphabetic cipher and in essence implements many Caesar's ciphers with different keys. 


##### Implementation
Both the encryption and decryption are utilized in the function below. The enc_dec parameter is 1 for encryption and 0 for decryption. If the key is shorter than the message, it is repeated until it reaches the size of the message.

``` c
unsigned char* vigenere_crypto(unsigned char* msg, unsigned char* key, bool enc_dec) 
```
* **Encryption**
    1. The table of alphabets is generated in the function  ```tabularRecta()```. Each row and column contains the alphabet where the *i* row is shifted i position to the left. Same for columns.
    The alphabet set used is the [0-9A-Za-z]
    2. Each character of the key represents the row index *i* as its position on the alphabet(-1) and the plaintext represents the column index *j*.
    3. The characters of the ciphertext are all the *tabularRecta[i][j]*

* **Decryption**
    1. Each character of the key represents the row index *i* and then the function ``` vigeDecFindCol(char c,int row)``` searches for the cipher character on the row *i*.
    2. The character of the plaintext is the *tabular[0][col]* for which *tabular[i][col] = cipher*

    
### Helper functions

* ```generateKey()```: Generate a key based on the unix PSG /dev/urandom
* ```charToHex()```: Convert a character array to hex values
* ```hexToChar()```: Convert an array with hex values to string
* ```cleanText()```: Strips a string of characters not in [a-zA-Z0-9]
* ```setAlphabet()```: Set the alphabet for caesar's cipher
* ```vigeDecFindCol()```: On vigener's cipher, find decryption char' column index.

