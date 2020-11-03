CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.o rsa.o utils.o

AM = 2013030068
TARGET = assign_3


all: $(TARGET) keygen encrypt

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) -lm	

keygen: 
	./$(TARGET) -g 

encrypt:
	./${TARGET} -i ../files/hpy414_encryptme_pub.txt -k ../files/hpy414_public.key -o ../files/${AM}_encrypted_pub.txt -e

clean:
	rm -f $(TARGET) *.o
