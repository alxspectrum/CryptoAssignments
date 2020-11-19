CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic -Wextra 
OBJFILES = main.o rsa.o utils.o

AM = 2013030068
TARGET = assign_3

all: $(TARGET) keygen encryptpub encryptpriv decryptpub decryptpriv

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) -lm	

keygen: 
	./$(TARGET) -g 

encryptpub:
	./${TARGET} -i ../files/hpy414_encryptme_pub.txt -k ../files/hpy414_public.key -o ../files/TUC${AM}_encrypted_pub.txt -e

encryptpriv:
	./${TARGET} -i ../files/hpy414_encryptme_priv.txt -k ../files/hpy414_private.key -o ../files/TUC${AM}_encrypted_priv.txt -e

decryptpub:
	./${TARGET} -i ../files/hpy414_decryptme_pub.txt -k ../files/hpy414_public.key -o ../files/TUC${AM}_decrypted_pub.txt -d

decryptpriv:
	./${TARGET} -i ../files/hpy414_decryptme_priv.txt -k ../files/hpy414_private.key -o ../files/TUC${AM}_decrypted_priv.txt -d


# TEST
enctest:
	./${TARGET} -i ../files/hpy414_encryptme_pub.txt -k ../files/private.key -o ../files/enctest.txt -e 

dectest:
	./${TARGET} -i ../files/enctest.txt -k ../files/public.key -o ../files/dectest.txt -d 


clean:
	-rm -f $(TARGET) *.o
	-rm -f ../files/TUC*.txt ../files/private.key ../files/public.key