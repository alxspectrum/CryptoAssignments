CC = gcc

ZIP = 2013030068_assign6

CFLAGS = -Wall -Wextra -std=gnu99 -O2 -D_GNU_SOURCE 
CPPFLAGS =
LDFLAGS = -lpcap

all: monitor 

monitor: monitor.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test:
	./monitor -i enp4s0
# 	./monitor -i wlp5s0
# 	./monitor -r test_pcap_5mins.pcap
# 	./monitor -r test_pcap_ipv6.pcap


clean:
	-rm *.o
	-rm monitor
	-rm output.txt

zip: *.[ch] Makefile README.md
	mkdir -p "$(ZIP)"
	cp $^ "$(ZIP)/"
	tar -czvf "$(ZIP).zip" "$(ZIP)"
