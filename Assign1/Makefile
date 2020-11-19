ifndef DBG
DBG=1
endif

CC=gcc
CFLAGS= -Wall -Wextra -D_GNU_SOURCE -std=c99 -Wno-pointer-sign
DEBUGFLAGS= -g

VALGRINDFLAGS=--track-origins=yes --leak-check=full -s
DBG=1
ifeq ($(DBG),1)
CFLAGS += $(DEBUGFLAGS)
endif

OBJFILES = simple_crypto.o demo.o
TARGET = demo

all: $(TARGET) run

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

run:
	./$(TARGET)

debug:
	valgrind ${VALGRINDFLAGS} ./${TARGET}

clean:
	-rm -f $(OBJFILES) *~ *.zip $(ZIP)


ZIP = 2013030068_assign1
ZIPFILES = *.c *.h Makefile README.md ${TARGET} 

zip:
	-make clean
	-zip -r $(ZIP).zip ${ZIPFILES}