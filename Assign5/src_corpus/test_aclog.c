#include <stdio.h>
#include <string.h>
#include <unistd.h>


int main(int argc, char* argv[]) 
{

	FILE *fp = NULL;
	if (argc < 2) {
		printf("Did not pass any files\n");
		return 1;
	}

	if (argc%2==0) {
		printf("Did not pass value to write to file\n");
		return 1;
	}

	for (int i = 1; i < argc; i+=2) {
		fp = fopen(argv[i], "w");
		if (fp != NULL) {
			fwrite(argv[i+1], strlen(argv[i+1]), 1, fp);
			fclose(fp);
		}
	}

	return 0;
}
