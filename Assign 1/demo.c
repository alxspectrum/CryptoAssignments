/*
* Main program crypto_algorithms.c
* Calls: OTP, Caesar, Vigenere
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simple_crypto.h"


int main() {

	char* algorithm;

	// OTP
	algorithm = "OTP";
	printAlg(algorithm);

	// CAESAR 	
	algorithm = "Caesars";
	printAlg(algorithm);

	// VIGENERE
	algorithm = "Vigenere";
	printAlg(algorithm);

	printf("\n");
	return 0;
}

