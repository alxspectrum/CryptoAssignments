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
	setuid(8);


	/* example source code */

	for (i = 0; i < 0; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) {
			printf("asdsd\n");
			printf("fopen error\n");
		}
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

	// printf("%d\n", getuid());
	unsigned char *msg = "a";
	file = fopen("create", "w");
	for (int i = 0; i < 1; ++i) fwrite(msg, strlen(msg), 1, file);		

	fclose(file);

	file = fopen("create", "a");
	for (int i = 0; i < 1; ++i) fwrite(msg, strlen(msg), 1, file);
	fclose(file);
	
	file = fopen("create", "w");
	for (int i = 0; i < 1; ++i) fwrite(msg, strlen(msg), 1, file);
	fclose(file);		
	// }
	// // fwrite((char*)"write2", 6, 1, file);
	// fclose(file);
	// seteuid((uid_t)(999));
	// printf("%d\n", geteuid());
	// file = fopen("create", "a");
	// fwrite(msg, strlen(msg), 1, file);

	printf("Success!\n");

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


}
