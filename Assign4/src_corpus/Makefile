all: logger acmonitor test_aclog run 

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

monitor:
	./acmonitor -a
	./acmonitor -m
	./acmonitor -i file_1
	
val:
	LD_PRELOAD=./logger.so valgrind ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf file*
