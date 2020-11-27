## Access Control Logging

### Description

This software implements:
* A logger which logs file operations(r-w-a) and the respective permissions of the user. 
* A tool that monitors suspicious non authorized access, file modifications, and user stats

### !Disclaimer 
This software is for auditing purposes only as it has not 
been tested on many different scenarios and security vulnerabilities. 

### Implementation 

##### Log
```bash

Each entry in the log file is in the following format:
UID: user id
Filename: absolute path of file 
Date: dd/mm/yy
Timestamp: hr/min/sec
Accesstype: {0, 1, 2}
IsActionDeniedFlag: {0, 1}
FileFingerprint: 16 byte MD5 hash
```

##### Monitor
```bash
usage:
	./acmonitor 
Options:
-m, Prints malicious users
-i <filename>, Prints table of users that modified the file <filename> and the number of modifications
-a, Prints full stats for every user
-h, Help message

```

#### Results
The software completes all the operations successfully.

#### Known Issues
When a file is created, it is assumed that the user has permission on the directory to write. (should check permission of directory)
May bug if the user gives as input to fopen in logger a file with '../'.