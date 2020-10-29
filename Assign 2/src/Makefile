CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic -Wno-return-type -Wextra
LIBSSL = -lssl -lcrypto -lm

TARGETS = assign_1
VALGRIND = valgrind
VALGRINDFLAGS= --leak-check=full --track-origins=yes

ENCRYPT_TARGET= ../files/decryptme_256.txt 
DECRYPT_TARGET= ../files/hpy414_encryptme_128.txt
SIGN_TARGET= ../files/verifyme_128.txt
VERIFY_TARGET_INPUT1= ../files/hpy414_verifyme_128.txt
VERIFY_TARGET_INPUT2= ../files/hpy414_verifyme_256.txt

TEST_TARGET= ../files/test.txt

FILES=${ENCRYPT_TARGET} ${DECRYPT_TARGET} ${SIGN_TARGET} ${TEST_TARGET}

# Task F
all: $(TARGETS) encrypt decrypt sign verify

test: sign testverify

assign_1: assign_1.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

# Task B
encrypt:
	./$(TARGETS) -i ../files/encryptme_256.txt -o ${ENCRYPT_TARGET} -p TUC2013030068 -e -b 256

# Task C
decrypt:
	./$(TARGETS) -i ../files/hpy414_decryptme_128.txt -o ${DECRYPT_TARGET} -p hpy414 -d -b 128

# Task D
sign:
	./${TARGETS} -i ../files/signme_128.txt -o ${SIGN_TARGET} -p TUC2013030068 -s -b 128

# Task E
verify:
	./${TARGETS} -i ${VERIFY_TARGET_INPUT1} -o . -p hpy414 -v -b 128
	./${TARGETS} -i ${VERIFY_TARGET_INPUT2} -o . -p hpy414 -v -b 256		



# Tests
testverify:
	./${TARGETS} -i ../files/verifyme_128.txt -o ${TEST_TARGET} -p TUC2013030068 -v -b 128

testdecrypt:
	./$(TARGETS) -i ../files/decryptme_256.txt -o ${TEST_TARGET} -p TUC2013030068 -d -b 256

# Debug

debug:
	${VALGRIND} ${VALGRINDFLAGS} ./${TARGETS} -i ${VERIFY_TARGET_INPUT2} -o . -p hpy414 -v -b 256

clean:
	-rm ../files/${FILES}
	rm -f $(TARGETS)
