#include "rsa.h"
#include "utils.h"



/*
 * Big-Endian system
 * Converts bytes to size_t type
 * @param {unsigned char*} bytes Sequence of bytes
 * @param {int} size Length of sequence
 * @returns {size_t} The bytes converted to size_t number
 */
size_t
bytesToSize_t(unsigned char* bytes, int size)
{
	unsigned char tmp[sizeof(size_t)];
	size_t result;
	int k = size-1;

	/* Can be skipped for Little Endian system */
	for (int i = 0; i < sizeof(size_t); ++i) {
		tmp[i] = bytes[k];
		k--;
	}
	
	result = bytes[0] + (bytes[1] << 8) + (bytes[2] << 16) + (bytes[3] << 24) + (bytes[4] << 32) + (bytes[5] << 40) + (bytes[6] << 48) + (bytes[7] << 56);
	return result;
}


/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes = malloc(limit * sizeof(size_t));
	size_t sieve_array[limit];
	size_t p;
	int k;

	/* Init array */
	for (int i = 0; i < limit; ++i) {
		sieve_array[i] = 1;
	}
	/* 0 and 1 are not primes */
	sieve_array[0] = 0;
	sieve_array[1] = 0;

	/* Mark all multiples of 2 as not prime */
	p = 2;
	while (pow(p,2) < limit) {

		/* Mark all multiples of p as not prime */
		for (int i = 2*p; i < limit; i+=p) {
			sieve_array[i] = 0;
		}

		/* Get next prime */
		for (int i = p+1; i < limit; ++i) {
			if (sieve_array[i] == 1) {
				p = i;
				break;
			}
		}
	}

	/* Store primes to another array */
	k = 0;
	for (int i = 0; i < limit; ++i) {
		if (sieve_array[i] == 1) {
			primes[k] = i;
			// printf("%zu\n", primes[k]);
			k++;
		}
	}


	*primes_sz = k;

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	int q,r;
	do {
		q = a/b;
		r = a % b;
		a = b;
		b = r;
	} while(b!=0);

	return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e;

	/* TODO */

	return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
	size_t mod;
	for (int i = 1; i < b; ++i) {
		if ((a*i)%b == 1) {
			mod = (size_t)i;
			return mod;
		}
	}

	/* Since gcd */
	printf("Modular inverse not found\n");
	printf("GCD of %zu, %zu is not 1\n",a,b);
	return -1;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	int primes_sz;
	size_t *primes = NULL;

	/* Init primes array */
	primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);

	/* Init random number generator */
    srand(time(0)); 
	
	/* Pick random primes q and p */	
	p = primes[rand() % primes_sz];
	q = primes[rand() % primes_sz];

	/* Compute n = p*q */
	n = p*q;

	/* Compute Euler Totient fi_n */
	fi_n = (p-1)*(q-1);

	/* Choose e */
	primes = sieve_of_eratosthenes(fi_n, &primes_sz);
	for (int i = 0; i < primes_sz; ++i) {
		e = primes[i];
		if ((e % fi_n != 0) && (gcd(e,fi_n) == 1)) break;
		if (i == primes_sz - 1) {
			printf("Did not find e to satisfy conditions\n");
			abort();
		}
	}

	/* Calcute modular inverse of (e,fi_n) */
	d = mod_inverse(e,fi_n);

	/* Store keys to respective files */
	FILE *fp;
	fp = fopen("../files/private.key","w");
	if (fp == NULL) {
		printf("Error opening file...\n");
		abort();
	}

	printf("%lu\n", n);
	/* Write numbers to file */
    fwrite(&n, sizeof(char), sizeof(size_t), fp);
    fwrite(&e, sizeof(char), sizeof(size_t), fp);
    fclose(fp);

	fp = fopen("../files/public.key","w");
	if (fp == NULL) {
		printf("Error opening file...\n");
		abort();
	}

	/* Write numbers to file */
    fwrite(&n, sizeof(char), sizeof(size_t), fp);
    fwrite(&d, sizeof(char), sizeof(size_t), fp);
    fclose(fp);

    /* Clean up */
	printf("Keys generated successfully!\n");
	free(primes);
	return;
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

	unsigned char* plaintext = NULL;
	unsigned char* ciphertext = NULL;
	unsigned char* key = NULL;

	int len = 0;
	FILE *fp;
	
	/* Read input file */
	fp = fopen(input_file, "r");
	if (fp == NULL) {
		printf("Error writing file...\n");
		abort();
	}

	/* Get length of plaintext */
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	plaintext = malloc(sizeof(char) * len);
	fread(plaintext, 1, len, fp);
	fclose(fp);

	/* Read Key file */
	fp = fopen(key_file, "r");
	if (fp == NULL) {
		printf("Error writing file...\n");
		abort();
	}

	/* Allocate mem for split key (8 bytes) */
	key = malloc(sizeof(size_t));

	/* Read n */
	fread(key, sizeof(char), sizeof(size_t), fp);
	size_t n = bytesToSize_t(key, sizeof(size_t));
	
	/* Read e */
	fread(key, sizeof(char), sizeof(size_t), fp);
	size_t e = bytesToSize_t(key, sizeof(size_t));


	fclose(fp);
	/* Clean up */
	free(key);
	free(plaintext);
	printf("Text encrypted successfully!\n");
	return;
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */

}
