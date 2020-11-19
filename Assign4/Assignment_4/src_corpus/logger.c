#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <fcntl.h>

#define FILE_CREATE 0
#define FILE_READ 1
#define FILE_WRITE 2
#define MD5_DIGEST_LENGTH 16
#define MAX_SIZE 4096

void
ExitError(char *errorMsg) {
	printf("%s\n", errorMsg); 
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


typedef struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	unsigned char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

} entry;

/**
 * Find the name of the file from
 * file descriptor
 */
char *
find_filename(FILE *fp){
	int MAXSIZE = 0xFFF;
    char proclnk[MAXSIZE];
    char *filename = malloc(sizeof(char) * 255);
    int fno;
    ssize_t r;

    if (fp != NULL) {
        fno = fileno(fp);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        r = readlink(proclnk, filename, MAXSIZE);
        if (r < 0) {
            printf("failed to readlink\n");
            exit(1);
        }
        
        filename[r] = '\0';
    }
    return filename;
}

/**
 * Store a byte array to a string
 *
 */
unsigned char*
bytesToString(unsigned char *bytes, int size) {
	unsigned char *buf = malloc(sizeof(char) * size);	
	if (buf == NULL) ExitError("No memory");
	unsigned char *result = malloc(sizeof(char) * 2 * size);
	if (result == NULL) ExitError("No memory");

	for (int i = 0; i < 2 * size; ++i) {
		result[i] = (unsigned char)0;
	}

	for (int i = 0; i < size; ++i) {
		snprintf((char*)buf, size, "%02X", bytes[i]);
		strcat((char*)result, (char*)buf);
	}

	result[MD5_DIGEST_LENGTH * 2 + 1] = '\0';
	free(buf);
	return result;
}

/**
 * Return MD5 hash of data
 * @returns MD5_DIGEST_LENGTH byte string 
 */
unsigned char*
hash(unsigned char *data, int length) {
	unsigned char *digest = malloc(MD5_DIGEST_LENGTH * sizeof(char));
	if (digest == NULL) ExitError("No memory");
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, data, length);
	MD5_Final(digest, &context);
	return digest;
}

/**
 * Read and hash the contents
 * of a file concat with the
 * contents to be written
 *
 * @returns hash of data
 */
unsigned char *
hash_contents(char *path, void *ptr) {
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	unsigned char *fingerprint = NULL;
	unsigned char *plaintext = NULL;

	FILE *sig = original_fopen(path, "r");
	if (sig != NULL) {
		fseek(sig, 0, SEEK_END);
		long len = ftell(sig);
		fseek(sig, 0, SEEK_SET);
		len += strlen(ptr);

		// String init to avoid strcat bugs
		plaintext = malloc(sizeof(char) * (len + 1));	
		for (int i = 0; i < len + 1; ++i) {
			plaintext[i] = (unsigned char)0;
		}
		fread(plaintext, 1, len, sig);
		plaintext[len] = '\0';

		if (strlen(ptr) > 0) {
			strcat((char*)plaintext, (char*)ptr);
		}	

	  	fingerprint = hash(plaintext, len);	
	  	free(plaintext);
	}
	else
		ExitError("cannot read file");

	fclose(sig);

	return fingerprint;
}

/* Check file open mode and user permission */
int*
get_access_type(const char *path, const char *mode)
{	
	static int result[2];

	/* File Creation */
	if (!strcmp(mode, "w") || !strcmp(mode, "w+") 
		|| !strcmp(mode, "a") || !strcmp(mode, "a+")){
		result[0] = (access(path, F_OK) == -1) ? FILE_CREATE:FILE_WRITE;
		result[1] = (access(path, W_OK) == -1) ? 1:0;
	}

	/* File Read */
	if (!strcmp(mode, "r") || !strcmp(mode, "r+")){
		result[0] = FILE_READ;
		result[1] = (access(path, R_OK) == -1) ? 1:0;
	}

	return result;
}


/**
 * Create the log message to
 * append to the logger
 */
char*
create_log(struct entry e) {
	char *logResult = malloc(MAX_SIZE * sizeof(char));

	if (logResult == NULL) ExitError("No memory");

	char buf[MAX_SIZE];
	strcpy(logResult, "UID: ");
	snprintf(buf, sizeof(buf), "%d", e.uid);
	strcat(logResult, buf);
	strcat(logResult, "\nFilename: ");
	if (e.access_type != 0) {
		strcat(logResult, realpath(e.file, buf));
	}
	else {
		strcat(logResult, realpath(".", buf));
		snprintf(buf, sizeof(buf), "/%s", e.file);
		strcat(logResult, buf);
	}
	strcat(logResult, "\nDate: ");
	snprintf(buf, sizeof(buf), "%d", (int)(e.date));
  	struct tm tm = *localtime((const time_t*)(&e.date));
	snprintf(buf, sizeof(buf), "%d %d %d", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
	strcat(logResult, buf);
	strcat(logResult, "\nTimestamp: ");
	snprintf(buf, sizeof(buf), "%02d:%02d:%0d", tm.tm_hour, tm.tm_min, tm.tm_sec);
	strcat(logResult, buf);
	strcat(logResult, "\nAccesstype: ");
	snprintf(buf, sizeof(buf), "%d", e.access_type);
	strcat(logResult, buf);
	strcat(logResult, "\nIsActionDeniedFlag: ");
	snprintf(buf, sizeof(buf), "%d", e.action_denied);
	strcat(logResult, buf);
	strcat(logResult, "\nFileFingerprint: ");
	snprintf(buf, sizeof(buf), "%s", bytesToString(e.fingerprint, MD5_DIGEST_LENGTH));
	strcat(logResult, buf);
	strcat(logResult, "\n\n");

	return logResult;
}

FILE *
fopen(const char *path, const char *mode) 
{

	/* Declare original open */
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	// Declare original write
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	// Get values for attributes
	int uid = (int)geteuid();
	int *access = get_access_type(path, mode);
	int access_type = *access;
	int action_denied = *(access+1);
	time_t t = time(NULL);
	unsigned char *fingerprint = hash((unsigned char*)"", 0);

	// Generate file hash if file exists
	struct stat sb;
	if (stat(path, &sb) == 0) {
		fingerprint = hash_contents((char*)path, (void*) "");
	}

  	// Store all args to struct
	entry *e = malloc(sizeof(struct entry));
	if (e == NULL) ExitError("No memory");
  	e->uid = uid;
  	e->access_type = access_type;
  	e->action_denied = action_denied;
  	e->date = t;
  	e->time = t;
  	e->file = (char*)path;
  	e->fingerprint = fingerprint;
  	seteuid(1000);
	FILE *log = original_fopen("./file_logging.log", "a");

  	// Create log from struct fields
  	char *logResult = NULL;
  	logResult = create_log(*e);
	original_fwrite(logResult, sizeof(char), strlen(logResult), log);

  	// Append log to logger
	if (log == NULL) {
		printf("fopen error\n");
		// exit(EXIT_FAILURE);
		return NULL;	
	}
	
	// Clean up
	fclose(log);
	free(logResult);
	free(e);
	free(fingerprint);

	// Continue to original fopen
	original_fopen_ret = (*original_fopen)(path, mode);
	return original_fopen_ret;
}

/**
 * Find mode of file descriptor
 * based on the flag and file number
 *
 */
const char *
get_mode_of_fd(FILE *stream)
{	
	int fno = fileno(stream);
	int modeno = fcntl(fno, F_GETFL);

	switch (modeno){
		case(32768):
			return "r";
		case(32769):
			return "w";
		case(33793):
			return "a";
		case(32770):
			return "w+";
		case(33794):
			return "a+";
	}
	
	return "Non supporting file mode";
}

/**
 * Get status code of write
 * based on mode 
 * e.g should not log write 
 * on "r" mode
 *
 */
int
get_status_of_write(FILE *stream)
{	
	int fno = fileno(stream);
	int modeno = fcntl(fno, F_GETFL);

	switch (modeno){
		case(32768):
			return 2;
		case(32769):
			return 0;
		case(33793):
			return 1;
		case(32770):
			return 0;
		case(33794):
			return 1;
	}
	
	return -1;
}

size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	// Set FILE stream to not use buffer
	setbuf(stream, NULL);

	// Declare original open
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	// Declare original write
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	// Get mode of FD
	const char *mode = get_mode_of_fd(stream);
	int status = get_status_of_write(stream);
	if (status == 2 || status == -1){
		original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
		return original_fwrite_ret;		
	} 

	// Get values for attributes
	int uid = (int)geteuid();
	char *path = find_filename(stream);
	int *access = get_access_type(path, mode);
	int access_type = *access;
	int action_denied = *(access+1);
	time_t t = time(NULL);
	unsigned char *fingerprint = NULL;

	// Handle status code
	if (status == 1) 
		fingerprint = hash_contents(path,(void*) ptr);
	else if (status == 0)
		fingerprint = hash((unsigned char*)ptr, size);

  	// Store all args to struct
	entry *e = malloc(sizeof(struct entry));
  	e->uid = uid;
  	e->access_type = access_type;
  	e->action_denied = action_denied;
  	e->date = t;
  	e->time = t;
  	e->file = path;
  	e->fingerprint = fingerprint;

  	// Create log from struct fields
  	char *logResult = NULL;
  	logResult = create_log(*e);

  	// Append log to logger
	FILE *log = original_fopen("./file_logging.log", "a+");
	if (log == NULL) {
		printf("fopen error\n");
		exit(EXIT_FAILURE);
	}
	original_fwrite(logResult, sizeof(char), strlen(logResult), log);
	
	// Clean up
	fclose(log);
	free(logResult);
	free(e);
	free(fingerprint);
	free(path);

	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	return original_fwrite_ret;
}
