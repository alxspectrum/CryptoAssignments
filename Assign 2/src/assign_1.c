#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16
#define CMAC_SIZE 16

int SHA_DIGEST_LENGTH = 0;

/* function prototypes */
void exitError();
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
unsigned char* keygen(unsigned char *, int, int);
unsigned char* encrypt(unsigned char *, int, unsigned char *, unsigned char *
	, int);
unsigned char* decrypt(unsigned char *, int, unsigned char *, unsigned char *
	, int);
unsigned char* gen_cmac(unsigned char *, size_t, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */

void
printInfo(char *msg) {
	printf("%s\n", msg);
	return;
}

void
printTask(char *msg) {
	printf(" ======= %s =======\n", msg);
}

void
printDebug() {
	printf("\n Debug point \n");
}

/**
 * Print errors to stdout
 * and exit program
 */
void
exitError(){
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
unsigned char*
keygen(unsigned char *password, int pass_len, int bit_mode) 
{
	printInfo("Generating key...");

	unsigned char *key = malloc(32 * sizeof(char));
	if (!EVP_Digest (password, pass_len , key, NULL, EVP_sha1(), NULL)) exitError();

	/* PAD THE KEY */
	if (bit_mode == 256) {
		for (int i = 20; i < SHA_DIGEST_LENGTH; ++i) {
			key[i] = 0;
		}
	}

	printInfo("Key generated!");
	return key;
}


/*
 * Encrypts the data
 */
unsigned char*
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, int bit_mode)
{
	printInfo("Encrypting plaintext of file...");
	
	/* Initialization */
	unsigned char* ciphertext = NULL;
	int ciphertext_len = 0;
	int outlen = 0;

	/* Get next multiple of block size of the plaintext */
	ciphertext_len = (plaintext_len / BLOCK_SIZE) * (BLOCK_SIZE) + BLOCK_SIZE;
	ciphertext = malloc(ciphertext_len * sizeof(char));

	/* Create and initialize context */
	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) goto err;

	/* Initialize encryption operation using AES_ECB Algorithm */
	if (bit_mode == 128 ) {
		if (!(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))) goto err;
	} 
	else if (bit_mode == 256) {
		if (!(EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))) goto err;
	}
	else {
		printf("Bit mode %d not supported\n", bit_mode);
		abort();
	}

	/* Encrypt the plaintext and store it to the ciphertext */
	if (!(EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len))) goto err;
	ciphertext_len = outlen;
	
	/* Finalize ciphertext encrypting any extra bytes */
	if (!(EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen))) goto err;
	ciphertext_len += outlen;

	/* Clean up */
	EVP_CIPHER_CTX_cleanup(ctx);

	printInfo("Plaintext encrypted successfully!");
	return ciphertext;

	/* Handle errors */
	err:
		EVP_CIPHER_CTX_free(ctx);
		free(ciphertext);
		exitError();
}


/*
 * Decrypts the data and returns the plaintext size
 */
unsigned char*
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, int bit_mode)
{
	printInfo("Decrypting the ciphertext...");

	/* Initialization */
	unsigned char* plaintext_buffer = NULL;
	int plaintext_len;
	int outlen;

	/* Allocate memory for the plaintext */
	plaintext_buffer = malloc((ciphertext_len) * sizeof(char));

	/* Initialize the context */
	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) goto err;

	/* Initialize the decryption operation depending on the bit_mode */
	if (bit_mode == 128){
		if (!(EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))) goto err;
	}
	else if (bit_mode == 256) {
		if (!(EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))) goto err;	
	}
	else {
		printf("Bit mode %d not supported\n", bit_mode);
		goto err;
	}

	/* Decrypt the plaintext */
	if (!(EVP_DecryptUpdate(ctx, plaintext_buffer, &outlen, ciphertext, ciphertext_len))) goto err;
	plaintext_len = outlen;

	/* Finalize decryption */
	if (!(EVP_DecryptFinal_ex(ctx, plaintext_buffer + outlen, &outlen))) goto err;
	plaintext_len += outlen;
	plaintext_buffer[plaintext_len] = '\0';

	EVP_CIPHER_CTX_free(ctx);

	printInfo("Ciphertext decrypted!");
	return plaintext_buffer;

	err:
		EVP_CIPHER_CTX_free(ctx);
		free(plaintext_buffer);
		exitError();
}


/*
 * Generates a CMAC
 */
unsigned char*
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    int bit_mode)
{

	printInfo("Generating CMAC...");
	size_t cmac_len;
	unsigned char* cmac = malloc(CMAC_SIZE * sizeof(char));
	CMAC_CTX *ctx;

	/* Initialize CMAC context */
	if (!(ctx = CMAC_CTX_new())) goto err;

	/* Initialize CMAC generation operation depending on bit_mode */
	if (bit_mode == 128) {
		if (!CMAC_Init(ctx, key, SHA_DIGEST_LENGTH, EVP_aes_128_ecb(), NULL)) goto err;
	} 
	else if (bit_mode == 256){
		if (!CMAC_Init(ctx, key, SHA_DIGEST_LENGTH, EVP_aes_256_ecb(), NULL)) goto err;
	}
	else {
		printf("Bit mode %d not supported\n", bit_mode);
		goto err;
	}

	/* Generate the CMAC of data */
	if (!CMAC_Update(ctx, data, data_len)) goto err;
	
	/* Finalize the operation */
	if (!CMAC_Final(ctx, cmac, &cmac_len)) goto err;

	/* Clean up*/
	CMAC_CTX_free(ctx);
	printInfo("CMAC generated successfully!");
	return cmac;

	/* Handle Errors */
	err:
		CMAC_CTX_free(ctx);
		free(cmac);
		exitError();
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify = 0;

	verify = strcmp((char*)cmac1,(char*)cmac2) == 0 ? 1 : 0;

	return verify;
}



/* TODO Develop your functions here... */


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */


	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);
	
	/* Initialization */

	SHA_DIGEST_LENGTH = bit_mode/8; /* Get number of Bytes */
	unsigned char *plaintext = NULL;
	unsigned char *ciphertext = NULL;
	unsigned char *key = NULL;		/* key derived from kdf */
	unsigned char *iv = NULL;		/* */
	unsigned char *cmac = NULL;
	unsigned char *cmac_of_plaintext = NULL;

	int pass_len;            /* password length */
	int plaintext_len;  	 /* length of plaintext */
	int ciphertext_len;		/* length of ciphertext*/
	long fsize = 0;     /* Size of data in file */

	/* Key generation */
	printInfo("################ EVP OPERATIONS ################");
	printTask("Task A");

	pass_len = strlen((char*)password);
	key = keygen(password, pass_len, bit_mode);

	/* Operate on the data according to the mode */
	FILE *fp;
	iv = malloc(BLOCK_SIZE * sizeof(char));
	
	// RAND_bytes(iv, BLOCK_SIZE);
	iv = (unsigned char*)"1234567812345678";
	iv = NULL;
	/* Encryption */
	if (op_mode == 0) {
		printTask("Task B");
		if (!(fp = fopen(input_file,"r"))) goto err;
		
		/* Get length of the plaintext */
		if (fseek(fp, 0, SEEK_END)) goto err;
		fsize = ftell(fp);
		if (fseek(fp, 0, SEEK_SET)) goto err;

		/* Read plaintext from file */
		plaintext = malloc(fsize * sizeof(char));
		if (!(fread(plaintext, 1, fsize, fp))) goto err;
		fclose(fp);

		plaintext_len = fsize;

		/* Ciphertext length - Multiple of Block Size */
		ciphertext_len = (plaintext_len / BLOCK_SIZE) * (BLOCK_SIZE) + BLOCK_SIZE;		

		/* Encrypt the plaintext */
		ciphertext = encrypt(plaintext, plaintext_len, key, iv, bit_mode);		
		
		/* Write the ciphertext to output file */
		if (!(fp = fopen(output_file,"w"))) goto err;
		if (!fwrite(ciphertext, 1, ciphertext_len, fp)) goto err;
		
		/* Clean up */
		fclose(fp);
		free(plaintext); 
		free(ciphertext);
	}
	
	/* Decryption */
	if (op_mode == 1) {
		printTask("Task C");
		if (!(fp = fopen(input_file,"r"))) goto err;
		
		/* Get ciphertext size */
		if (fseek(fp, 0, SEEK_END)) goto err;
		fsize = ftell(fp);
		if (fseek(fp, 0, SEEK_SET)) goto err;

		/* Allocate memory and read ciphertext */
		ciphertext = malloc((fsize + BLOCK_SIZE) * sizeof(char));
		if (!(fread(ciphertext, 1, fsize, fp))) goto err;
		fclose(fp);

		/* Get plaintext length - Should be multiple of blocksize */
		ciphertext_len = fsize;

		/* Decrypt ciphertext */	
		plaintext = decrypt(ciphertext, ciphertext_len, key, iv, bit_mode);				
		plaintext_len = strlen((char*)plaintext);

		/* Write decrypted text to file */
		if (!(fp = fopen(output_file,"w"))) goto err;
		if (!fwrite(plaintext, 1, plaintext_len, fp)) goto err;
		
		/* Free */
		fclose(fp);
		free(plaintext); 
		free(ciphertext);
	}

	/* Sign */
	if (op_mode == 2) {
		printTask("Task D");
		
		if (!(fp = fopen(input_file,"r"))) goto err;

		/* Get length of plaintext */
		if (fseek(fp, 0, SEEK_END)) goto err;
		fsize = ftell(fp);
		if (fseek(fp, 0, SEEK_SET)) goto err;

		/* Read plaintext from file */
		plaintext = malloc(fsize * sizeof(char));
		if (!(fread(plaintext, 1, fsize, fp))) goto err;
		fclose(fp);

		/* Get ciphertext length */
		plaintext_len = fsize;
		ciphertext_len = (plaintext_len / BLOCK_SIZE) * (BLOCK_SIZE) + BLOCK_SIZE;		
		/* Encrypt text */
		ciphertext = encrypt(plaintext, plaintext_len, key, iv, bit_mode);					
		
		/* Generate CMAC */
		cmac = gen_cmac(plaintext, plaintext_len, key, bit_mode);

		/* Concatenate CMAC to ciphertext */
		if (!(fp = fopen(output_file,"w"))) goto err;
		if (!fwrite(ciphertext, 1, ciphertext_len, fp)) goto err;
		if (fseek(fp, 0, SEEK_END)) goto err;
		if (!fwrite(cmac, 1, CMAC_SIZE, fp)) goto err;
		fclose(fp);
		
		/* Clean up */
		free(cmac);
		free(ciphertext);
		free(plaintext);
	}

	/* Verify */
	if (op_mode == 3) {
		printTask("Task E");
		
		plaintext = NULL;
		if(!(fp = fopen(input_file,"r"))) goto err;

		/* Get the size of ciphertext + CMAC */
		if (fseek(fp, 0, SEEK_END)) goto err;
		fsize = ftell(fp);
		if (fseek(fp, 0, SEEK_SET)) goto err;

		/* Allocate MEM for ciphertext and cmac */
		ciphertext = malloc((fsize - CMAC_SIZE) * sizeof(char));
		cmac = malloc(CMAC_SIZE * sizeof(char));
		
		/* Extract ciphertext and CMAC*/
		if (!(fread(ciphertext, 1, fsize - CMAC_SIZE, fp))) goto err;
		if (!(fread(cmac, 1, CMAC_SIZE, fp))) goto err;
		fclose(fp);

		/* Get ciphertext length */
		ciphertext_len = fsize - CMAC_SIZE;

		/* Decrypt the ciphertext */
		plaintext = decrypt(ciphertext, ciphertext_len, key, iv, bit_mode);	
		plaintext_len = strlen((char*)plaintext);
		
		/* Generate CMAC */
		cmac_of_plaintext = gen_cmac(plaintext, plaintext_len, key, bit_mode);

		/* Verify Signature */
		int verify = verify_cmac(cmac, cmac_of_plaintext);
		if (verify) {
			printInfo("Success: Signer authenticated!");

			/* Write plaintext to output file */
			if (!(fp = fopen(output_file,"w"))) goto err;
			if (!fwrite(plaintext, 1, plaintext_len, fp)) goto err;
			fclose(fp);
		}
		else printInfo("Failure: Authentication failed: Different CMAC");

		/* Clean up */
		free(cmac);
		free(ciphertext);
		free(plaintext);
	}		

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	/* END */
	printInfo("################ SUCCESS ################");
	return 0;

	/* Handle errors */
	err:
		fclose(fp);
		free(cmac);
		free(ciphertext);
		free(plaintext);
		exitError();
}
