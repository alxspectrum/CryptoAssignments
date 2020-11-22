#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	unsigned char *msg = "a";
	char *nopermfile = "noperm";

	// Create
	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w");
		if (file == NULL) {
			printf("fopen error\n");
		}
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

	// Should deny 20 times for UID 1000
	// Should modify 41 times file_0 UID 1000
	// Should modify 21 times file_1
	// Should modify 11 times file_2
	for (int i = 0; i < 2; ++i)
	{
		// No permission. Deny
		for (int i = 0; i < 10; ++i) {
			file = fopen(nopermfile, "a");
			if (file != NULL){
				fwrite(msg, strlen(msg), 1, file);	
				fclose(file);
			}
		}

		// Modify
		file = fopen("file_0", "a");
		if (file != NULL){
			for (int i = 0; i < 10; ++i) fwrite(msg, strlen(msg), 1, file);	
			fclose(file);
		}
	
		// Modify
		file = fopen("./file_0", "a");
		if (file != NULL){
			for (int i = 0; i < 10; ++i) fwrite(msg, strlen(msg), 1, file);	
			fclose(file);
		}

		// Modify
		file = fopen(filenames[1], "a");
		if (file != NULL){
			for (int i = 0; i < 10; ++i) fwrite(msg, strlen(msg), 1, file);	
			fclose(file);
		}

		// Modify 
		file = fopen(filenames[2], "a");
		if (file != NULL){
			for (int i = 0; i < 5; ++i) fwrite(msg, strlen(msg), 1, file);	
			fclose(file);
		}

		// Read
		file = fopen(filenames[2], "r");
		if (file != NULL){
			for (int i = 0; i < 5; ++i) fwrite(msg, strlen(msg), 1, file);	
			fclose(file);
		}
	}

	printf("Success!\n");
}
