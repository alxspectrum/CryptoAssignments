## Access Control Logging

### Description

This software implements a packet sniffing tool focusing on TCP and UDP packets on IP/IPv6

### !Disclaimer 
This software is for auditing purposes only as it has not 
been tested on many different scenarios and security vulnerabilities. 

### Run
On src_corpus directory:
```bash
make
```

##### Monitor
```bash
usage:
	./monitor [options] 
Options:
-i <device_name>, Live mode: Captures packets on given interface 
-r <pcap_file>, Offline mode: Captures packets from a given file 
-h, Help message

```

#### Results
The software completes all the operations successfully.

Q9. TCP packets are retransmitted in some cases such as:
	a. A timer expires when a sender does not receive acknowledgement
	b. The sender receives 3+ times a specific acknowledgement (Dup Acks)
	c. The sender receives an acknowledgement that is in the wrong order

We can tell if a TCP packet is retransmitted by checking if:
	a. The packet is not a keepalive packet
	b. The segment length is > 0 or the SYN or FIN flag is set
	c. The sequence number on the same packet flow is smaller than the previous max sequence number

Q10. There is no retransmission on UDP packets because there is no point of retransmission. UDP is used 
in connections where the endpoints don't need to have an accurate transmission because the message
is received even with less than 100% of the packets, such as a video call.

12.a. 
The total network flows are counted as the total number of distinct
	* Mac address connections (ethernet)
	* IPv4 connections
	* IPv6 connections
	* TCP network flows
	* UDP network flows

#### Known Issues
1. The software classifies as retransmissions the following Wireshark analytics:
	* Retransmissions
	* Spurious Retransmissions
	* Out-of-order
	* Fast Retransmissions

The accuracy is > 98%

Not captured retransmissions is due to the assumption that 
payload under 6 bytes is a padding so some packets with payloads
of length of 1-6 are skipped on the retransmission check.

2. The payload length includes padding.