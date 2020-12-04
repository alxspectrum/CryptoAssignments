#!/bin/bash

# Bash script for automatic
# creation/encryption/deletion
# of files

# Verify result funtion
verifyResult() {
	if [ $1 -ne 0 ]; then
		echo "Error: $2"
		exit 1
	fi
}

if [ -z "$1" ]; then
	echo "Error: missing directory"
	exit 1
fi

if [ -z "$2" ]; then
	echo "Error: missing number of files"
	exit 1
fi

# Args
DIR=$1
MAX_FILES=$2

# Constants
AM=2013030068
ITER=1000
CIPHER=-aes-256-ecb
DIGEST=md5
COUNT=0
files=""

# Remove all generated files
if [ "$2" == "clean" ]; then
	rm "$DIR"/encfile_*
	rm "$DIR"/file*

	exit 0
fi

# Decrypt
if [ "$2" == "dec" ]; then
	files="$(find "$DIR" -type f -name "*.encrypt")"
	if [ -z "$files" ]; then
		echo "No files found"
		exit 0
	fi
	for file in $files; do
		plaintext="$(openssl enc -a -d -md $DIGEST $CIPHER -iter $ITER -in "$DIR/$file" -pbkdf2 -k $AM)"
		file=${file%".encrypt"}
		LD_PRELOAD=./logger.so ./test_aclog "$file".decrypt "$plaintext"	
	done
	exit 0	
fi



# Create files in given directory
while [ $COUNT -lt $MAX_FILES ]; do
	val=encfile_"$COUNT"
	LD_PRELOAD=./logger.so ./test_aclog $val $val
	res=$?
	verifyResult $res "test_aclog failed to create files"
	files+="encfile_${COUNT} " 
	COUNT="$(expr $COUNT + 1)"
done

# Encrypt file 
# Pass encrypted text to logger 
# Delete original file 
for file in $files; do
	pass="$(openssl enc -a -md $DIGEST $CIPHER -iter $ITER -in "$DIR/$file" -pbkdf2 -k $AM)"
	pass="$pass"$'\n'
	LD_PRELOAD=./logger.so ./test_aclog "$file".encrypt "$pass"	
	res=$?	
	verifyResult $res "test_aclog failed to create encrypted files"
	rm $DIR/$file
done
sleep 1

exit 0




