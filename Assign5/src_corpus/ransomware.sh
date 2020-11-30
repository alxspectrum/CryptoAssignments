#!/bin/bash

# Bash script for automatic
# creation/encryption/deletion
# of files

# Verify result funtion
verifyResult() {
	if [ $1 -ne 0 ]; then
		echo "Error..."
		exit 1
	fi
}

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

# Create files in DIRectory
while [ $COUNT -lt $MAX_FILES ]; do
	val=encfile_"$COUNT"
	LD_PRELOAD=./logger.so ./test_aclog $val $val
	res=$?
	verifyResult $res
	files+="encfile_${COUNT} " 
	COUNT="$(expr $COUNT + 1)"
done

# Encrypt file 
# Pass encrypted text to logger 
# Delete original file 
for file in $files; do
	pass="$(openssl enc -a -md $DIGEST $CIPHER -iter $ITER -in "$DIR/$file" -pbkdf2 -k $AM)"
	pass="$pass"$'\n'
	echo $pass
	LD_PRELOAD=./logger.so ./test_aclog "$file".encrypt "$pass"	
	res=$?	
	verifyResult $res
	rm $DIR/$file
done
sleep 1

# # Decrypt
# for file in $files; do
# 	plaintext="$(openssl enc -a -d -md $DIGEST $CIPHER -iter $ITER -in "$DIR/$file".encrypt -pbkdf2 -k $AM)"
# 	# echo "$plaintext"
# done
# set -x
# LD_PRELOAD=./logger.so openssl enc -a -md $DIGEST $CIPHER -iter $ITER -in encfile_0 -out ${PWD}/file.encrypt -pbkdf2 -k $AM





