#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 100
#define MAX_MODS 1000
#define ACT_DENIED 1
#define MD5_DIGEST_HASH 32
#define MAX_FILES 100
#define MAX_STR_LEN 120

/**
 * Keep user record with number of accesses
 *
 */
struct User {
	int uid;
	int accessno;
	int num_of_files;
	char files[MAX_FILES][MAX_STR_LEN];
	char checksums[MAX_FILES][MD5_DIGEST_HASH + 1];
	int mods[MAX_FILES];

};

// Create global arrays
struct User users[MAX_USERS];
int num_of_users = 0;

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./acmonitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-a, Prints full stats for every user\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

/**
 * Print all user stats
 */
void
print_stats() {
	for (int k = 0; k < num_of_users; ++k) {
		printf("UID: %d\n", users[k].uid);
		printf("Access denies: %d\n", users[k].accessno);

		for (int i = 0; i < users[k].num_of_files; ++i) {
			printf("File: %s\n", users[k].files[i]);
			printf("Hash: %s\n", users[k].checksums[i]);
			printf("Mods: %d\n", users[k].mods[i]);
		}
		printf("\n");
	}
}

/**
 * Find user by uid
 *
 **/
int
find_user_index(int uid)
{
	for (int i = 0; i < num_of_users; ++i) {
		if (users[i].uid == uid) return i; 
	}

	return -1;
}

/**
 * Check if file is added 
 * to user struct
 *
 */
int
file_index_on_user(int index, char *file) {
	for (int i = 0; i < users[index].num_of_files; ++i) {
		if (strcmp(users[index].files[i], file) == 0) return i;
	}

	return -1;
}

void
log_users(FILE *log)
{
	char *line = malloc(sizeof(char) * 256);
	size_t len = 0;
	int read = 0;
	char *value = NULL;
	int action = 0;
	int index = 0;
	int uid = 0;
	int file_index = 0;
	int new_file = 0;

	while ((read = getline(&line, &len, log)) != -1) {

		// Store uid
		if (strncmp(line, "UID:", 4) == 0) {
			value = strtok(line, " ");
			value = strtok(NULL, " ");

			sscanf(value, "%d", &uid);
			index = find_user_index(uid);

			if (index == -1) {
				users[num_of_users].uid = uid;
				users[num_of_users].accessno = 0;
				users[num_of_users].num_of_files = 0;
				users[num_of_users].mods[0] = 0;
				index = num_of_users;
				num_of_users++;
			}
		}

		// Store filename
		if (strncmp(line, "Filename:", 9) == 0) {
			value = strtok(line, " ");
			value = strtok(NULL, " ");
			value[strlen(value) - 1] = '\0';
			file_index = file_index_on_user(index, value);
			if (file_index == -1) {
		   		memset(users[index].checksums[users[index].num_of_files], '\0', MD5_DIGEST_HASH + 1);
				strncpy(users[index].files[users[index].num_of_files], value, strlen(value));
				users[index].mods[users[index].num_of_files] = 0;				
				users[index].num_of_files++;
				file_index = users[index].num_of_files - 1;
			}
		}


		// Store access denial
		if (strncmp(line, "IsActionDeniedFlag:", 17) == 0) {
			value = strtok(line, " ");
			value = strtok(NULL, " ");
			sscanf(value, "%d", &action);
			if (action == ACT_DENIED) 
				users[index].accessno++;
		}

		// Store file's fingerprint to check modifications
		if (strncmp(line, "FileFingerprint", 15) == 0) {
			value = strtok(line, " ");
			value = strtok(NULL, " ");
			value[strlen(value) - 1] = '\0';
			
			if (strcmp(value, users[index].checksums[file_index]) == 0) {
				 continue;
			}
			if (action == ACT_DENIED) continue;
			if (strlen(users[index].checksums[file_index]) > 1)
				users[index].mods[file_index]++;

			// Copy new fingerprint
		   	memset(users[index].checksums[file_index], '\0', MD5_DIGEST_HASH + 1);
			strncpy(users[index].checksums[file_index], value, MD5_DIGEST_HASH);
		}
	};

	return;
}

void 
list_unauthorized_accesses(FILE *log)
{	
	printf("!Malicious Users!\n");
	if (num_of_users == 0) {
		printf("No malicious users found\n");
		return;
	}
	for (int i = 0; i < num_of_users; ++i) {
		if (users[i].accessno >= 7) {
			printf("Malicious UID: %d\n", users[i].uid);
			printf("Access denied: %d times\n", users[i].accessno);
		}
	}
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	char *filepath = realpath(file_to_scan, NULL);
	if (filepath == NULL) {
		printf("File does not exist\n");
		return;
	}
	printf("%s\n", filepath);

	int userMods[MAX_USERS];
	int mods = 0; 
	for (int i = 0; i < num_of_users; ++i) {
		for (int k = 0; k < users[i].num_of_files; ++k) {
			if (strcmp(users[i].files[k], filepath) == 0) {
				printf("UID: %d Modifs: %d\n", users[i].uid, users[i].mods[k]);
				mods+= users[i].mods[k];
			}
		}
	}
	printf("Total modifications: %d\n", mods);

	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	log_users(log);
	while ((ch = getopt(argc, argv, "hi:ma")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'a':
			print_stats();
			break;
		default:
			usage();
		}

	}



	printf("\n");

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
