#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 100
#define MAX_MODS 1000
#define ACT_DENIED 1
#define MD5_DIGEST_HASH 32
#define MAX_FILES 1000
#define MAX_STR_LEN 120
#define TIME_PASSED 1200

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

struct File {
	char filename[MAX_STR_LEN];
	time_t unixtime;
};

// Create global arrays
struct User users[MAX_USERS];
struct File files[MAX_FILES];
int num_of_files = 0;
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
		   "-v <number of files>, Prints the total number of files "
		   "created in the last 20 minutes\n"
		   "-e, Prints all the files that were encrypted by the ransomware\n"
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
 * Print file stats
 *
 */
void
print_created_files() {
	for (int i = 0; i < num_of_files; ++i) {
		printf("Name: %s\n", files[i].filename);
		// printf("Date: %s\n", ctime(&(files[i].unixtime)));
		printf("%ld\n", files[i].unixtime);
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
file_index_on_user(int index, char *file)
{
	for (int i = 0; i < users[index].num_of_files; ++i) {
		if (strcmp(users[index].files[i], file) == 0) return i;
	}

	return -1;
}

/**
 * Check if file exists
 * on files array
 *
 */
int
file_index_on_files(char *file)
{
	for (int i = 0; i < num_of_files; ++i) {
		if (strcmp(files[i].filename, file) == 0) return i;
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
	int file_index_on_file = 0;
	int access_type = 0;
	struct tm tm = {};

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
			
			// User data
			value[strlen(value) - 1] = '\0';
			file_index = file_index_on_user(index, value);
			if (file_index == -1) {
		   		memset(users[index].checksums[users[index].num_of_files], '\0', MD5_DIGEST_HASH + 1);
				strncpy(users[index].files[users[index].num_of_files], value, strlen(value));
				users[index].mods[users[index].num_of_files] = 0;				
				users[index].num_of_files++;
				file_index = users[index].num_of_files - 1;
			}

			// File data
			file_index_on_file = file_index_on_files(value);
			if (file_index_on_file == -1) {
				memset(files[num_of_files].filename, '\0', MAX_STR_LEN);
				strncpy(files[num_of_files].filename, value, strlen(value));
				num_of_files++;
				file_index_on_file = num_of_files - 1;
			}
		}

		// Store date
		if (strncmp(line, "Date:", 4) == 0) {
			tm = (struct tm) {};
			value = strtok(line, " ");
			value = strtok(NULL, " ");
			value = strtok(value, "/");
			tm.tm_mday = atoi(value);
			value = strtok(NULL, "/");
			tm.tm_mon = atoi(value) - 1;
			value = strtok(NULL, "/");
			tm.tm_year = atoi(value) - 1900;
		}

		// Store time
		if (strncmp(line, "Timestamp:", 9) == 0) {
			value = strtok(line, " ");
			value = strtok(NULL, " ");
			value = strtok(value, ":");
			tm.tm_hour = atoi(value);
			value = strtok(NULL, ":");
			tm.tm_min = atoi(value);
			value = strtok(NULL, ":");
			tm.tm_sec = atoi(value);
		}

		// Get access type
		if (strncmp(line, "Accesstype:", 9) == 0) {
			value = strtok(line, " ");
			value = strtok(NULL, " ");
			sscanf(value, "%d", &access_type);
			if (access_type == 0) {
				files[file_index_on_file].unixtime = (time_t)0;
				files[file_index_on_file].unixtime = mktime(&tm);
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
		if (strncmp(line, "FileFingerprint:", 15) == 0) {
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

void
list_files_created(int filenum)
{
	// print_created_files();
	int num = 0;
	time_t now = time(NULL);

	printf("%d\n", num_of_files);
	for (int i = 0; (i < num_of_files && i < filenum); ++i) {
		if (now - files[i].unixtime < TIME_PASSED) num++;
	}

	printf("Total files created in the last %d minutes: %d\n", TIME_PASSED/60, num);
	return;
}


int 
main(int argc, char *argv[])
{

	int ch;
	int filenum;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	log_users(log);
	while ((ch = getopt(argc, argv, "hi:mav:e")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			filenum = atoi(optarg);
			list_files_created(filenum);
			break;
		case 'e':
			// 
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
