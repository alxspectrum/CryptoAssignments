/*
* simple_crypto.h
* A library consisting of cryptographic algorithms:
* One-time-pad, Caesar's cipher, Vigenere's cipher
*
* Author: Alexandros Tragkas
*
*/

#ifndef _SIMPLE_CRYPTO_H_
#define _SIMPLE_CRYPTO_H_

#include <stdbool.h>

/**
 * One time pad encryption function
 * @param {unsigned char*} msg The text message to be encrypted/decrypted
 * @param {unsigned char*} key The secret key to encrypt the message
 * @param {bool} enc_dec Value 0 to decrypt, 1 to encrypt
 * @returns {unsigned char*} cipher The cipher text
 */
unsigned char* otp_crypto(unsigned char *msg, unsigned char *key, bool enc_dec);

/**
 * Caesar's cipher encryption and decryption
 * @param {unsigned char*} msg The text message to be encrypted/decrypted
 * @param {int key} key The key for the letter shifting on caesar's cipher
 * @param {bool} enc_dec Value 0 to decrypt, 1 to encrypt
 * @returns {unsigned char*} The encrypted/decrypted text
 */
unsigned char* caesars_crypto(unsigned char* msg, int key, bool enc_dec);

/**
 * Generates key from /dev/urandom PSG
 * @param {int} size The size of the key (same or longer than plaintext)
 * @returns {unsigned char*} res The key in bytes
 */
unsigned char* generateKey(int size);

/**
 * Create the tabular recta for vigener's cipher
 * @returns {unsigned char**} The tabular recta
 */
unsigned char** tabularRecta();

/**
 * Vigener's sipher encryption and decryption
 * @param {unsigned char*} msg The text message to be encrypted/decrypted
 * @param {unsigned char*} key The key to use on the tabular recta
 * @param {bool} enc_dec Value 0 for decrypt, 1 to encrypt
 * @returns {unsigned char*} The encrypted/decrypted text
 */
unsigned char* vigenere_crypto(unsigned char* msg, unsigned char* key, bool enc_dec);

/**
 * Converts a character array to hex
 * @param {unsigned char*} text The text to be converted
 * @returns {unsigned char*} res The array with hex values
 */
unsigned char* charToHex(unsigned char *text);

/**
 * Converts a hex array to characters
 * @param {unsigned char*} hex The array in hex representation
 * @param {int} size The size of the array
 * @returns {unsigned char*} res The character array
 **/
unsigned char* hexToChar(unsigned char *hex, int size);

/**
 * Print bytes as hex value
 * @param {unsigned char*} bytes A byte array
 * @param {unsigned char*} size The sie of the array
 * @returns {void}
 */
void printBytesAsHex(unsigned char *bytes, int size);

/**
 * Strips text of characters not in [a-zA-Z0-9]
 * @param {unsigned char*} msg The plaintext
 * @returns {unsigned char*} The stripped plaintext
 */
unsigned char* cleanText(unsigned char *msg);

/**
 * Prints algorithm outputs in specific format
 * @param {char*} algo The execution algorithm
 * @param {unsigned char*} input User's input
 * @param {unsigned char*} cipherText Generated ciphertext
 * @param {unsigned char*} plainText Recovered text
 * @returns {void}
 */
void printAlg(char* algo);

#endif