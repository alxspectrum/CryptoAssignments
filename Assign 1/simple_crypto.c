#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdbool.h>

#define MAX_INPUT_SIZE 64
#define CAESARS_ALPHABET_SIZE (26+26+10)
#define ALPHABET_SIZE 26

void printBytesAsHex(unsigned char *bytes, int size) {
	for (int i = 0; i < size; ++i) {
		printf("%X", bytes[i]);
	}
	return;
}

char* setAlphabet() {

	/* Alphabet set is [0-9A-Za-z] */
	char *alphabet = malloc(CAESARS_ALPHABET_SIZE * sizeof(char));
	int ascii = 48;
	for (int i = 0; i < CAESARS_ALPHABET_SIZE; ++i) {
		alphabet[i] = (char)ascii;
		ascii++;
		if ( 58 == ascii ) ascii = 65;
		else if ( 91 == ascii ) ascii = 97;
		else if ( 123 == ascii ) break;
		else continue;
	}
	return alphabet;
}

unsigned char* charToHex(unsigned char *text) {

	unsigned char buffer[100];
	int size = strlen(text);
	unsigned char *hex = malloc(size * sizeof(unsigned char));
	int i=0;

	while (text[i] != '\0'){
		snprintf(buffer, 100, "%c", text[i]);
		hex[i]=buffer[0];
		i++;
	}

	return hex;
}

unsigned char* hexToChar(unsigned char *hex,int size) {

	unsigned char buffer[100];
	unsigned char *text = malloc(size * sizeof(unsigned char));

	for (int i = 0; i < size; ++i){
		snprintf(buffer, 100, "%c", hex[i]);
		text[i]=buffer[0];
	};
	
	// text[size]='\0';
	return text;
}

unsigned char** tabularRecta() {
	
	unsigned char **tabularRecta = malloc(ALPHABET_SIZE * sizeof(char*));	
	// char tabularRecta[ALPHABET_SIZE][ALPHABET_SIZE];	
	int asciiCaps=65;
	int k;
	for (int i = 0; i < ALPHABET_SIZE; ++i) {
		tabularRecta[i] = malloc(ALPHABET_SIZE * sizeof(char));
		k = i;
		for (int j = 0; j < ALPHABET_SIZE; ++j) {
			if (90 < k + asciiCaps) k = 0;
			tabularRecta[i][j] = k + asciiCaps;
			k++;
		}
	}
	return tabularRecta;
}

unsigned char* generateKey(int size) {

	unsigned char *buffer = malloc(size * sizeof(unsigned char));

	int fd = open("/dev/urandom", O_RDONLY);
	int res = read(fd, buffer, size);
	assert(res >= 0);
	close(fd);

	return buffer;
}

unsigned char* otp_crypto(unsigned char *msg, unsigned char *key, bool enc_dec) {

	// Length of message
	int size = strlen(msg);

	// Encrypt
	if (enc_dec) {
		unsigned char *cipher = malloc(size * sizeof(unsigned char));

		// Convert each unsigned char to hex 
		unsigned char* msgHex = charToHex(msg);

		// Encrypt by XORing each byte of msg with key
		for (int i = 0; i < size; ++i) {
			cipher[i] = msgHex[i] ^ key[i];
		}

		free(msgHex);
		return cipher;
	}
	// Decrypt
	else {
		unsigned char *plainHex = malloc(size * sizeof(unsigned char));
		unsigned char *plain;
		
		// Decrypt by XORing each byte of ciphertext with key
		for (int i = 0; i < size; ++i) {
			plainHex[i] = msg[i] ^ key[i];
		}

		plain = hexToChar(plainHex, size);
		free(plainHex);
		return plain;
	}
}

char findCaesarChar(char c, char* alphabet, int key, bool enc_dec) {

	for (int i = 0; i < CAESARS_ALPHABET_SIZE; ++i) {
		if ( (alphabet[i]) == c) {
			if(enc_dec) {  
				if (i + key >= CAESARS_ALPHABET_SIZE) {
					return alphabet[i + key - CAESARS_ALPHABET_SIZE];
				}
				else 
					return alphabet[i + key];
			} else if (!enc_dec) {
				if (i - key < 0) 
					return alphabet[i - key + CAESARS_ALPHABET_SIZE];
				else
					return alphabet[i - key];
			}
		} 
	}

	printf("\nError: Character %c not found in alphabet set", c);
	return '\0';
}

unsigned char* caesars_crypto(unsigned char* msg, int key, bool enc_dec) {
	
	int size = strlen((char*)msg);
	unsigned char *text = malloc(size * sizeof(char));
	unsigned char *alphabet = setAlphabet();

	for (int i = 0; i < size; ++i) {
		text[i] = findCaesarChar(msg[i], alphabet, key, enc_dec);
	}

	return text;
}

int vigeDecFindCol(char c,int row){
	
	unsigned char **alphabet = tabularRecta();
	for (int i = 0; i < ALPHABET_SIZE; ++i) {
		if ( c == alphabet[row][i] ) return i;
	}
	return -1;
}	

unsigned char* vigenere_crypto(unsigned char* msg, unsigned char* key, bool enc_dec) {

	int asciiCaps = 65;
	int size = strlen(msg);
	unsigned char **alphabet = tabularRecta();
	unsigned char *text = malloc(size * sizeof(char));
	unsigned char* extendedKey;

	// expand key
	if ((int)strlen(key) < size) {
		extendedKey = malloc(size * sizeof(char));
		int key_size = strlen(key);
		int key_index = 0;
		int ext_index = 0;
		while (ext_index < size) {
			if (key_index == key_size) key_index = 0;
			extendedKey[ext_index] = key[key_index];
			key_index++;
			ext_index++;
		}
	} 
	else if ((int)strlen(key) > size) {
		extendedKey = malloc(size * sizeof(char));
		for (int i = 0; i < size; ++i) {
			extendedKey[i] = key[i];
		}
	}
	else extendedKey = key;

	if (enc_dec) {
		for (int i = 0; i < size; ++i) {
			text[i] = alphabet[msg[i] - asciiCaps][extendedKey[i] - asciiCaps];
		}
	} 
	else {
		for (int i = 0; i < size; ++i) {
			text[i] = vigeDecFindCol(msg[i], extendedKey[i] - asciiCaps) + asciiCaps;
		}
	}

	if (extendedKey != NULL) free(extendedKey);
	return text;
}

unsigned char* cleanText(unsigned char *msg) {
	unsigned char *cleanMsg = malloc(strlen(msg) * sizeof(unsigned char));
	int j = 0;
	for (unsigned int i = 0; i < strlen((char*)msg); ++i) {
		if (msg[i] < 48) continue;
		else if (msg[i] > 57 && msg[i] < 65) continue;
		else if (msg[i] > 90 && msg[i] < 97) continue;
		else if (msg[i] > 122) continue;
		else {
			cleanMsg[j] = msg[i];
			j++;
		}
	}
	cleanMsg[j] = '\0';
	return cleanMsg;
}


void printAlg(char* algo) {

	unsigned char *input;
	unsigned char *plainText, *cipherText, *recoveredText;
	unsigned char* key;
	int textSize;
	int caesars_key;

	input = malloc(MAX_INPUT_SIZE * sizeof(unsigned char*));
	if (input == NULL) {
		printf("\nNo memory");
		return;
	}

	printf("\n[%s] input: ", algo);
	fgets(input, MAX_INPUT_SIZE*10, stdin);
	// input[strlen(input)] = '\0';
	plainText = cleanText(input);
	textSize = strlen((char*)plainText);
	// plainText[textSize] = '\0';

	/* KEY SECTION */
	if ( strcmp(algo, "Caesars") == 0 ) {
		int c;
		printf("[%s] key: ", algo);
		int res = scanf("%d", &caesars_key);
		if ( res == EOF ) return; 
		/* FLUSH STDIN */
		while ((c = getchar() != '\n') && (c != EOF))	{
			;;
		}
	} /* CAESARS */
	else if ( strcmp(algo,"Vigenere") == 0 ) {
		printf("[%s] key: ", algo);
		key = malloc(MAX_INPUT_SIZE);
		fgets(key, MAX_INPUT_SIZE, stdin);
		int key_size = strlen(key);
		if (key[key_size - 1] == '\n') key[key_size - 1] = '\0';
	} /* VIGENERE */
	else 
		key = generateKey(textSize); /* OTP */

	/* ALGORITHM EXECUTION */
	if ( strcmp(algo, "Caesars") == 0 ) {
		cipherText = caesars_crypto(plainText, caesars_key, 1);
		recoveredText = caesars_crypto(cipherText, caesars_key, 0);
	}  /*CAESARS*/ 
	else if ( strcmp(algo,"Vigenere") == 0 ) {
		cipherText = vigenere_crypto(plainText, key, 1);
		recoveredText = vigenere_crypto(cipherText, key, 0);
		free(key);
	} /* VIGENERE */
	else {
		cipherText = otp_crypto(plainText, key, 1);
		recoveredText = otp_crypto(cipherText, key, 0);
		free(key);
	} /* OTP */
	
	printf("[%s] encrypted: ", algo);
	if ( strcmp("OTP", algo) == 0 ) printBytesAsHex(cipherText, strlen(plainText));
	else printf("%s", cipherText);
	printf("\n[%s] decrypted: %s", algo, recoveredText);
	
	free(input);
	free(plainText);
	free(cipherText);
	free(recoveredText);
	// if (key != NULL) free(key);
	return;
}