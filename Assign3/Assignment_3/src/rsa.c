#include "rsa.h"
#include "utils.h"

/*
 * Little endian system
 * Converts bytes to size_t type
 * @param {unsigned char*} bytes Sequence of bytes
 * @param {int} size Length of sequence
 * @returns {size_t} result The bytes converted to size_t number
 */
size_t
bytesToSize_t(unsigned char* bytes, int size)
{
	int num = 1;
	size_t result;

	/* Check endianess */
	// if (*(char *)&num == 1) {
	//     printf("Little-Endian\n");
	// }
	// else {
	//     printf("Big-Endian\n");
	// }
	/* Function can be implemented for both endianness */
	/*unsigned char tmp[sizeof(size_t)];
	int k = size-1;

	for (int i = 0; i < sizeof(size_t); ++i) {
		tmp[i] = bytes[k];
		k--;
	}
	*/
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

	/* Mark all multiples of p as not prime till p^2 > limit */
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
	int primes_sz;
	size_t	*primes = sieve_of_eratosthenes(fi_n, &primes_sz);
	for (int i = 0; i < primes_sz; ++i) {
		e = primes[i];
		if ((e % fi_n != 0) && (gcd(e,fi_n) == 1)) break;
		if (i == primes_sz - 1) {
			printf("Did not find e to satisfy conditions\n");
			abort();
		}
	}
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
	e = choose_e(fi_n);

	/* Calcute modular inverse of (e,fi_n) */
	d = mod_inverse(e,fi_n);

	/* Store keys to respective files */
	FILE *fp;
	fp = fopen("../files/private.key","w");
	if (fp == NULL) {
		printf("Error opening file...\n");
		abort();
	}

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
 * Modular exponentiation
 *
 * @param {size_t} m 
 * @param {size_t} e
 * @param {size_t} n
 * @returns {size_t} res
 */
size_t
mod_exp(size_t m, size_t e, size_t n) {

	size_t res = 1;
	m = m % n;
	if (m == 0) return 0;
	while(e > 0) {
		if (e%2) res = (res*m) % n;
		e = e/2;
		m = (size_t)pow(m,2) % n;
	}
	return res;
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
	if (plaintext == NULL) {
		printf("No memory to allocate\n");
		abort();	
	}

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

	/* Open output file */
	fp = fopen(output_file, "w+");
	if (fp == NULL) {
		printf("Error opening file...\n");
		free(plaintext);
		free(key);
		abort();
	}

	/* Encrypt each byte */
	size_t ct;
	for (int i = 0; i < len; ++i) {
		ct = mod_exp(plaintext[i], e, n);
		fwrite(&ct, sizeof(char), sizeof(size_t), fp);
	}
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
	unsigned char* extended_ciphertext = NULL;
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

	extended_ciphertext = malloc(sizeof(size_t));
	if (extended_ciphertext == NULL) {
		printf("No memory to allocate\n");
		free(extended_ciphertext);
		abort();	
	}

	/*
	 * Read each size_t number from file 
	 * Convert it to size_t and store 
	 * it on ciphertext array  
	 */
	int ct_size = len/8;
	size_t ct;
	size_t *ciphertext = malloc(ct_size * sizeof(size_t));
	for (int i = 0; i < ct_size; ++i) {
		fread(extended_ciphertext, 1, sizeof(size_t), fp);
		ct = bytesToSize_t(extended_ciphertext, sizeof(size_t));
		ciphertext[i] = ct;
	}
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
	size_t d = bytesToSize_t(key, sizeof(size_t));
	fclose(fp);

	/* Open output file */
	fp = fopen(output_file, "w+");
	if (fp == NULL) {
		printf("Error opening file...\n");
		free(ciphertext);
		free(key);
		abort();
	}

	/* Decrypt each byte */
	char pt;
	unsigned char plaintext[ct_size]; 
	for (int i = 0; i < ct_size; ++i) {
		pt = (char)	mod_exp(ciphertext[i], d, n);
		plaintext[i] = pt;
	}

	fwrite(plaintext, sizeof(char), ct_size, fp);
	fclose(fp);

	/* Clean up */
	free(key);
	free(ciphertext);
	printf("Text decrypted successfully!\n");
	
	return;
}
