#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <signal.h>
#include <openssl/md5.h>

#define MAX_PACKETS 650000
#define MAX_FLOWS    20000
#define MD5_DIGEST_LENGTH 16

/**
 * Print help
 *
 */
void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor [options] \n"
		   "Options:\n"
		   "-i <device_name>, Live mode: Captures packets on given interface \n"
		   "-r <pcap_file>, Offline mode: Monitor packets from a given file \n" 
		   "-h, Help message\n\n"
		   );

	exit(0);
}

/**
 * A struct containing fields of a packet
 *
 */
struct Packet {
	/* Src and Dest IPs */
	char *src_ip;
	char *dst_ip;

	/* Src and Dest Ports */
	u_int src_port;
	u_int dst_port;

	/* Packet version and lengths */
	int version;
	int ip_header_length;
	int payload_length;

	/* Packet No. */
	int number;

	/* Protocol Name and header length */
	u_char *protocol;
	u_int16_t protocol_header_length;


	/* TCP SPECIFICS */
	long long time_captured;

	/* TCP FLAGS */
	u_int32_t seq;
	u_int32_t ack;
	u_int16_t rst;
	u_int16_t fin;
	u_int16_t psh;
	u_int16_t syn;
	u_int16_t urg;

	u_int16_t window;

	int retransmitted; /* 1 if this TCP packet is retransmitted */
};

/**
 * A struct containing network stats
 *
 */
struct Network {

	int total_netflows; /* Total network flows */
	int total_tcp;		/* Total TCP network flows */
	int total_udp;		/* * Total UDP network flows */
	
	int total_recv_packets; /* Total received packets */
	int total_recv_tcp; /* Total received TCP packets */
	int total_recv_udp; /* Total received UDP packets */

	int total_tcp_bytes; /* Total payload bytes of TCP packets*/
	int total_udp_bytes; /* Total payload bytes of UDP packets*/

	int total_ipv4_packets; /* Total IPv4 Packets */
	int total_ipv6_packets; /* Total IPv6 Packets */
};

/**
 * A packet flow
 *
 */
struct Flow {
	char *src_ip;
	char *dst_ip;

	u_int src_port;
	u_int dst_port;

	int protocol;

	u_int32_t seq;
	u_int32_t next_seq;
};

char hostIP[INET_ADDRSTRLEN];
char hostIPv6[INET6_ADDRSTRLEN];

struct Flow flows[MAX_FLOWS];
struct Flow tcp_flows[MAX_FLOWS];
int total_tcp_flows = 0;
int total_retr = 0;

struct Network network = {0};
struct Packet packets[MAX_PACKETS];

/**
 * Return time in ms
 *
 */
long long 
time_in_ms(void) {
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}

/**
 * Get IPv4 and IPv6 of host
 * by device name
 *
 */
void
get_hostIP_by_name(char *device) {
	struct ifaddrs *ifa, *tmp;
	char addr[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifa) == -1) {
	    printf("Failed to get addresses");
	    exit(1);
	}

	/* Loop through all devices to find the current's device IPs */
	tmp = ifa;
	while (tmp) {
	    if ((tmp->ifa_addr) && (
	    	(tmp->ifa_addr->sa_family == AF_INET) 
	    	|| (tmp->ifa_addr->sa_family == AF_INET6)
	    	)) {
	    	/********** IPv4 *********/
	        if (tmp->ifa_addr->sa_family == AF_INET
	        	&& (strncmp(device, tmp->ifa_name, strlen(device)) == 0)) 
	        {
	            struct sockaddr_in *in = (struct sockaddr_in*) tmp->ifa_addr;
	            inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
		        memcpy(hostIP, addr, INET_ADDRSTRLEN);
	        } 
	    	/********** IPv6 *********/
	        else if (strcmp(device, tmp->ifa_name) == 0)
	        {
	            struct sockaddr_in6 *in6 = (struct sockaddr_in6*) tmp->ifa_addr;
	            inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
		        memcpy(hostIPv6, addr, INET6_ADDRSTRLEN);
	        	break;
	        }

	    }
	    tmp = tmp->ifa_next;
	}

	freeifaddrs(ifa);
}

/**
 * Get IPv6 from IPv4
 *
 */
void
get_ipv6_by_ipv4() {
	struct ifaddrs *ifa, *tmp;
	char addr[INET6_ADDRSTRLEN];
	char *name = NULL;

	if (getifaddrs(&ifa) == -1) {
	    printf("Failed to get addresses");
	    exit(1);
	}

	/* Loop through all devices to find the current's device IPs */
	tmp = ifa;
	while (tmp) {
	    if ((tmp->ifa_addr) && (
	    	(tmp->ifa_addr->sa_family == AF_INET) 
	    	|| (tmp->ifa_addr->sa_family == AF_INET6)
	    	)) {
	    	/********** IPv4 *********/
	        if (tmp->ifa_addr->sa_family == AF_INET) 
	        {
	            struct sockaddr_in *in = (struct sockaddr_in*) tmp->ifa_addr;
	            inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
	            if (strcmp(addr, hostIP) == 0) {
	            	name = tmp->ifa_name;
	            }
	        } 
	    	/********** IPv6 *********/
	        else if (strcmp(name, tmp->ifa_name) == 0)
	        {
	            struct sockaddr_in6 *in6 = (struct sockaddr_in6*) tmp->ifa_addr;
	            inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
		        memcpy(hostIPv6, addr, INET6_ADDRSTRLEN);
	        	break;
	        }

	    }
	    tmp = tmp->ifa_next;
	}

	freeifaddrs(ifa);
}

/**
 * Prints flows
 *
 */
void
print_flows() {
	for (int i = 0; i < network.total_netflows; ++i) {
		printf("Source IP: %s\n", flows[i].src_ip);
		printf("Dest   IP: %s\n", flows[i].dst_ip);
		printf("Source Port: %d\n", flows[i].src_port);
		printf("Dest   Port: %d\n", flows[i].dst_port);
		printf("Protocol: %d\n", flows[i].protocol);
		printf("\n");
	}
}
/**
 * Print all network interfaces
 *
 */
void
print_network_interfaces() {

	char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
	pcap_if_t *interfaces, *temp;
	int i = 0;

	/* Find all devices */
	if (pcap_findalldevs(&interfaces, error_buffer) == -1) {
		printf("Error finding devices: %s\n", error_buffer);
		return;
	}

	/* Print all device names */
	for(temp = interfaces; temp; temp=temp->next) {
		printf("%d  :  %s\n", i++, temp->name);
	}

	return;
}

/**
 * Compare 2 packets for similarity
 * to detect retransmission
 *
 */
int
compare_packets(struct Packet pac1, struct Packet pac2) {

	if (pac1.seq == pac2.seq 
		&& ((pac1.ack == pac2.ack) || (pac2.ack == (pac1.ack + 1)))
		&& (strcmp(pac1.src_ip, pac2.src_ip) == 0) 
		&& (strcmp(pac1.dst_ip, pac2.dst_ip) == 0)
		&& (strcmp((const char*) pac1.protocol, (const char*) pac2.protocol) == 0)
		&& pac1.protocol_header_length == pac2.protocol_header_length
		&& pac1.version == pac2.version 
		&& pac1.ip_header_length == pac2.ip_header_length
		&& pac1.payload_length == pac2.payload_length
		&& pac1.src_port == pac2.src_port
		&& pac1.dst_port == pac2.dst_port
		&& pac1.fin == pac2.fin
		&& pac1.rst == pac2.rst
		&& pac1.psh == pac2.psh
		&& pac1.urg == pac2.urg
		&& pac1.syn == pac2.syn
		&& pac1.window == pac2.window
		)
		return 1;

	return 0;
}

/**
 * Find a packet's flow index from list
 *
 */
int 
get_tcp_flow(struct Packet packet) {
	for (int i = 0; i < total_tcp_flows; ++i) {
		
		if (strcmp(tcp_flows[i].src_ip, packet.src_ip) == 0
			&& strcmp(tcp_flows[i].dst_ip, packet.dst_ip) == 0
			&& tcp_flows[i].src_port == packet.src_port
			&& tcp_flows[i].dst_port == packet.dst_port
			)
		{
			return i;
		}
	}

	return -1;
}

void
add_tcp_flow(struct Flow flow) {

	for (int i = 0; i < total_tcp_flows; ++i) {
		if (strcmp(tcp_flows[i].src_ip, flow.src_ip) == 0
			&& strcmp(tcp_flows[i].dst_ip, flow.dst_ip) == 0
			&& tcp_flows[i].src_port == flow.src_port
			&& tcp_flows[i].dst_port == flow.dst_port
			&& tcp_flows[i].protocol == flow.protocol 
			){

			if (tcp_flows[i].seq <= flow.seq) {
				tcp_flows[i].seq = flow.seq;
				tcp_flows[i].next_seq = flow.next_seq;
			}

			return;
		}
	}

	tcp_flows[total_tcp_flows] = flow;
	total_tcp_flows++;

	return;
}
/**
 * If the received packet has the same
 * sequence number as an old packet,
 * it might be retransmitted
 *
 */
int
is_retransmitted(struct Packet pac) {

	int index = get_tcp_flow(pac);
	if (index == -1) return 0;

	if (((pac.syn || pac.fin)
		|| (pac.payload_length > 6))
		&& pac.seq > 0
		&& tcp_flows[index].next_seq > 0
		&& pac.seq < tcp_flows[index].next_seq)
		{
			total_retr++;
			return 1;
	}

	return 0;
}

/**
 * Print info of a packet
 *
 */
void
print_packet(struct Packet packet) {
	printf("	--- Packet No. %d --- \n", packet.number);
	printf("Packet Version: %d\n", packet.version);
	printf("Packet Source IP: %s\n", packet.src_ip);
	printf("Packet Dest   IP: %s\n", packet.dst_ip);
	printf("Packet Source Port: %d\n", packet.src_port);
	printf("Packet Dest   Port: %d\n", packet.dst_port);
	printf("Packet IP HL: %d\n", packet.ip_header_length);
	printf("Packet Protocol: %s\n", packet.protocol);
	printf("Packet Protocol HL (bytes): %hu\n", packet.protocol_header_length);
	printf("Packet Payload L (bytes): %d \n", packet.payload_length);

	if (strncmp((const char*)packet.protocol, (const char*)"TCP", 3) == 0) {
		printf("Packet Sequence number (raw): %u\n", packet.seq);
		printf("Packet Ack (raw): %u\n", packet.ack);
		if (packet.retransmitted) {
			printf("Packet Retransmitted\n");
		}
	}

	printf("\n");
}

/**
 * Print results found
 *
 */
void
print_network_stats() {

	printf("Network flows captured: %d\n", network.total_netflows);
	printf("TCP network flows captured: %d\n", network.total_tcp);
	printf("UDP network flows captured: %d\n", network.total_udp);
	printf("Total packets received: %d \n", network.total_recv_packets);
	printf("TCP packets received: %d\n", network.total_recv_tcp);
	printf("UDP packets received: %d\n", network.total_recv_udp);
	printf("TCP (bytes) received: %d\n", network.total_tcp_bytes);
	printf("UDP (bytes) received: %d\n", network.total_udp_bytes);
	printf("Total IPv4 packets received: %d\n", network.total_ipv4_packets);
	printf("Total IPv6 packets received: %d\n", network.total_ipv6_packets);
	printf("Total Retransmissions: %d\n", total_retr);
	printf(" \n");
}

/**
 * Print info of all packets captured
 *
 */
void
print_all_packets() {
	for (int i = 0; i < network.total_netflows; ++i) {
		print_packet(packets[i]);
	}
}

/**
 * Handle termination signal Ctrl+C
 *
 */
void
handle_sigint() {
	print_network_stats();
	exit(0);
}



/**
 * Find if a flow is unique
 * and add 
 *
 */
void
process_flow(struct Flow flow) {


	for (int i = 0; i < network.total_netflows; ++i) {
		if ((strcmp(flows[i].src_ip, flow.src_ip) == 0
			&& strcmp(flows[i].dst_ip, flow.dst_ip) == 0
			&& flows[i].src_port == flow.src_port
			&& flows[i].dst_port == flow.dst_port
			&& flows[i].protocol == flow.protocol 
			) || 
			(strcmp(flows[i].src_ip, flow.dst_ip) == 0
			&& strcmp(flows[i].dst_ip, flow.src_ip) == 0
			&& flows[i].src_port == flow.dst_port
			&& flows[i].dst_port == flow.src_port
			&& flows[i].protocol == flow.protocol 
			)){

			return;
		}
	}

	flows[network.total_netflows] = flow;
	network.total_netflows++;

	if (flow.dst_port != 0 && flow.src_port != 0){
		if (flow.protocol == IPPROTO_TCP) network.total_tcp++;
		else if (flow.protocol == IPPROTO_UDP) network.total_udp++;
	}
	
	return;
}

/**
 * Capture network traffic
 *
 */
void
packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
	const u_char *packet) {

	// IPv4
	struct ether_header *eth_header;
	struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;

	char sourceIP[INET_ADDRSTRLEN];
	char destIP[INET_ADDRSTRLEN];

	char etherIP[ETH_ALEN*4];

	// IPv6 
	struct ipv6hdr *ip6_hdr;

	char sourceIP6[INET6_ADDRSTRLEN];
	char destIP6[INET6_ADDRSTRLEN];

	// Header 
	int ether_header_len = 14;
	int ip_header_len;
	int tcp_header_len;
	int full_header_len;

	int payload_len;
	u_char protocol;
	int version;

	struct Flow flow;

	// Unknown protocol flag
	int unknown = 0;
	
	if (packet == NULL) {
		printf("No packet captured\n");
		return;
	}

	/* Ethernet Header is always 14 bytes */
	eth_header = (struct ether_header *) packet;
	
	snprintf(etherIP, sizeof(etherIP), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth_header->ether_shost[0], 
         eth_header->ether_shost[1], 
         eth_header->ether_shost[2], 
         eth_header->ether_shost[3], 
         eth_header->ether_shost[4], 
         eth_header->ether_shost[5] 
         );

	flow.src_ip = strdup(etherIP);
	snprintf(etherIP, sizeof(etherIP), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth_header->ether_dhost[0], 
         eth_header->ether_dhost[1], 
         eth_header->ether_dhost[2], 
         eth_header->ether_dhost[3], 
         eth_header->ether_dhost[4], 
         eth_header->ether_dhost[5] 
         );

	flow.dst_ip = strdup(etherIP);
	flow.protocol = 0;
	flow.src_port = 0;
	flow.dst_port = 0;

	process_flow(flow);

	/************************************************/
	/********************* IPv4 *********************/
	/************************************************/	
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
	
		/* Create packet instance */
		struct Packet pac = {};
		pac.retransmitted = 0;

		/* Get IP struct */
		ip_hdr = (struct ip*)(packet + ether_header_len);

	    /* Get IHL */
		pac.ip_header_length = ip_hdr->ip_hl * 4;

		/* Get Src and Dest Addresses */
		inet_ntop(AF_INET, &(ip_hdr->ip_src), sourceIP, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip_hdr->ip_dst), destIP, INET_ADDRSTRLEN);
		pac.src_ip = sourceIP;
		pac.dst_ip = destIP;

		flow.src_ip = strdup(sourceIP);
		flow.dst_ip = strdup(destIP);

	    ip_header_len = ip_hdr->ip_hl * 4;

		/* Get Version */
	    version = ip_hdr->ip_v;
	    pac.version = version;

	    /* Get Protocol */
	    protocol = ip_hdr->ip_p;
	    flow.protocol = protocol;
		process_flow(flow);

	    pac.number = network.total_recv_packets + 1;

	    /* Received IPv4 Packet */
		network.total_ipv4_packets++;


	    if (version == 4) {

			/************************************************/
			/********************* TCP **********************/
			/************************************************/			
			if (protocol == IPPROTO_TCP) {
				pac.protocol = (unsigned char*)"TCP";

				/* Start of TCP header */
				tcp_hdr = (struct tcphdr*)(packet + ether_header_len + ip_header_len);

				/* Get TCP HL */
			    tcp_header_len = (unsigned int)(tcp_hdr->doff) * 4;
				pac.protocol_header_length = tcp_header_len;

				/* Start of payload */
				full_header_len = ip_header_len + ether_header_len + tcp_header_len;

				/* Payload Size */
				payload_len = packet_header->caplen - full_header_len;
				pac.payload_length = payload_len;

				/* Get Source and Dest Ports */
				pac.src_port = ntohs(tcp_hdr->source);
				pac.dst_port = ntohs(tcp_hdr->dest);
				flow.src_port = pac.src_port;
				flow.dst_port = pac.dst_port;

				/* Time captured */
				pac.time_captured = time_in_ms();

				/* Get Sequence and Acknowlegement values (Raw) */
				pac.seq = ntohl(tcp_hdr->seq);
				pac.ack = ntohl(tcp_hdr->ack_seq);
				pac.rst = 1 & tcp_hdr->rst;
				pac.fin = 1 & tcp_hdr->fin;
				pac.psh = 1 & tcp_hdr->psh;
				pac.syn = 1 & tcp_hdr->syn;
				pac.urg = 1 & tcp_hdr->urg;
				pac.window = ntohs(tcp_hdr->window);

				flow.seq = ntohl(tcp_hdr->seq);
				flow.next_seq = ntohl(tcp_hdr->seq) + payload_len;
				
				if (pac.syn) {
					flow.next_seq = ntohl(tcp_hdr->seq) + 1;
				} else if (payload_len <= 6) {
					flow.next_seq = ntohl(tcp_hdr->seq);
				}

				
				if (is_retransmitted(pac)) pac.retransmitted = 1;
				add_tcp_flow(flow);

				/* Check for retransmittion */

				/* Received TCP packet */
				network.total_recv_tcp++;
				network.total_tcp_bytes += packet_header->caplen;

			} 

			/************************************************/
			/********************* UDP **********************/
			/************************************************/
			else if (protocol == IPPROTO_UDP) {
				pac.protocol = (unsigned char*)"UDP";

				/* Get Source and Dest Ports */
				udp_hdr = (struct udphdr*)(packet + ether_header_len + ip_header_len);
				pac.src_port = ntohs(udp_hdr->source);
				pac.dst_port = ntohs(udp_hdr->dest);
				flow.src_port = pac.src_port;
				flow.dst_port = pac.dst_port;

			    /* UDP Header is always 8 bytes and the rest is the payload */
				pac.protocol_header_length = 8;

				/* Payload Size */
				pac.payload_length = ntohs(udp_hdr->len) - pac.protocol_header_length;

				/* Received UDP packet */
				network.total_recv_udp++;
				network.total_udp_bytes += packet_header->caplen;

				/* Captured UDP network flow */

			}
			/************ UNHANDLED PROTOCOL ***********/
			else
				unknown = 1;

			if (!unknown) print_packet(pac);

			packets[network.total_recv_packets] = pac;

	   }

	} 
	/************************************************/
	/********************* IPv6 *********************/
	/************************************************/
	else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {

		/* Create packet instance */
		struct Packet pac = {};
		pac.retransmitted = 0;

		/* Get IP6 struct */
		ip6_hdr = (struct ipv6hdr*)(packet + ether_header_len);

	    /* Get IHL */
		pac.ip_header_length = 40;

		/* Get Src and Dest Addresses */
		inet_ntop(AF_INET6, &(ip6_hdr->saddr.s6_addr), sourceIP6, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ip6_hdr->daddr.s6_addr), destIP6, INET6_ADDRSTRLEN);
		
		pac.src_ip = sourceIP6;
		pac.dst_ip = destIP6;
		flow.src_ip = strdup(sourceIP6);
		flow.dst_ip = strdup(destIP6);

		process_flow(flow);

	    ip_header_len = 40;

		/* Get Version */
	    pac.version = ip6_hdr->version;

	    /* Get Protocol */
	    protocol = ip6_hdr->nexthdr;
	    flow.protocol = protocol;

	    pac.number = network.total_recv_packets + 1;

	    /* Received IPv6 Packet */
		network.total_ipv6_packets++;		
		
		if (pac.version == 6) {

			/************************************************/
			/********************* TCP **********************/
			/************************************************/
			if (protocol == IPPROTO_TCP) {
				pac.protocol = (unsigned char*)"TCP";

				tcp_hdr = (struct tcphdr*)(packet + ether_header_len + ip_header_len);

				/* Get TCP HL */
			    tcp_header_len = (unsigned int)(tcp_hdr->doff) * 4;
				pac.protocol_header_length = tcp_header_len;

				/* Start of payload */
				full_header_len = ip_header_len + ether_header_len + tcp_header_len;

				/* Payload Size */
				payload_len = packet_header->caplen - full_header_len;
				pac.payload_length = payload_len;

				/* Get Source and Dest Ports */
				pac.src_port = ntohs(tcp_hdr->source);
				pac.dst_port = ntohs(tcp_hdr->dest);
				flow.src_port = ntohs(tcp_hdr->source);
				flow.dst_port = ntohs(tcp_hdr->dest);

				/* Time captured (for retransmission check) */
				pac.time_captured = time_in_ms();

				/* Get Sequence and Acknowlegement values (Raw) */
				pac.seq = ntohl(tcp_hdr->seq);
				pac.ack = ntohl(tcp_hdr->ack_seq);
				pac.rst = 1 & tcp_hdr->rst;
				pac.fin = 1 & tcp_hdr->fin;
				pac.psh = 1 & tcp_hdr->psh;
				pac.syn = 1 & tcp_hdr->syn;
				pac.urg = 1 & tcp_hdr->urg;
				pac.window = ntohs(tcp_hdr->window);

				flow.seq = ntohl(tcp_hdr->seq);
				flow.next_seq = ntohl(tcp_hdr->seq) + payload_len;
				
				if (pac.syn) {
					flow.next_seq = ntohl(tcp_hdr->seq) + 1;
				} else if (payload_len <= 6) {
					flow.next_seq = ntohl(tcp_hdr->seq);
				}

				/* Check for retransmittion */
				if (is_retransmitted(pac)) pac.retransmitted = 1;
				add_tcp_flow(flow);

				/* Received TCP packet */
				network.total_recv_tcp++;
				network.total_tcp_bytes += packet_header->caplen;

			}
			/************************************************/
			/********************* UDP **********************/
			/************************************************/
			else if (protocol == IPPROTO_UDP) {
				pac.protocol = (unsigned char*)"UDP";

				/* Get Source and Dest Ports */
				udp_hdr = (struct udphdr*)(packet + ether_header_len + ip_header_len);
				pac.src_port = ntohs(udp_hdr->source);
				pac.dst_port = ntohs(udp_hdr->dest);
				flow.src_port = pac.src_port;
				flow.dst_port = pac.dst_port;

			    /* UDP Header is always 8 bytes and the rest is the payload */
				pac.protocol_header_length = 8;

				/* Payload Size */
				pac.payload_length = ntohs(udp_hdr->len) - pac.protocol_header_length;

				/* Received UDP packet */
				network.total_recv_udp++;
				network.total_udp_bytes += packet_header->caplen;

			}
			/************ UNHANDLED PROTOCOL ***********/
			else
				unknown = 1;
		}

		if (!unknown) print_packet(pac);

		packets[network.total_recv_packets] = pac;

	} 
	// else 

	network.total_recv_packets++;
	process_flow(flow);

}

/**
 * Print live network packets
 *

 */
void
monitor_live_traffic(char *device) {
	char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

   	pcap_t *handle;    
   	int packet_count_limit = 0;
   	int timeout_limit = 100000;

	handle = pcap_open_live(
		device,
		BUFSIZ,
		packet_count_limit,
		timeout_limit,
		error_buffer
	);

	if (handle == NULL) {
		printf("Error opening device %s\n", device);
		printf("Check device name or permission \n");
		printf("Exiting...\n");
		exit(1);
	}

   	printf("Device: %s\n", device);

    get_hostIP_by_name(device);
    printf("Host IPv4: %s\n", hostIP);
    printf("Host IPv6: %s\n\n", hostIPv6);

    signal(SIGINT, handle_sigint);

	int res = 1;
    while (res > 0) {
    	if ((res = pcap_loop(handle, packet_count_limit, packet_handler, NULL)) < 1) {
    		switch(res) {
    			case 0:
    				printf("Limit reached\n");
    				break;
    			case -1:
    				printf("Error on pcap loop\n");
    				break;
    		}
    	}
	}
}

/**
 * Monitor traffic from file
 *
 */
void
monitor_offline_traffic(char *filename) {

	char error_buffer[PCAP_ERRBUF_SIZE];
   	int packet_count_limit = 0;
	pcap_t *handle;

	printf("Opening file %s...\n", filename);

	handle = pcap_open_offline(filename, error_buffer);
	if (handle == NULL) {
		printf("Error opening file \n");
	}

 	char hostbuffer[256]; 
    struct hostent *host_entry; 
 
    // Get caller's IP
    gethostname(hostbuffer, sizeof(hostbuffer)); 
    host_entry = gethostbyname(hostbuffer); 
    strcpy(hostIP, 
    	inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]))); 

    get_ipv6_by_ipv4();

	int res = 1;
    while (res > 0) {
    	if ((res = pcap_loop(handle, packet_count_limit, packet_handler, NULL)) < 1) {
    		switch(res) {
    			case 0:
    				// printf("Limit reached\n");
    				break;
    			case -1:
    				printf("Error on pcap loop\n");
    				break;
    		}
    	}
	}

	print_network_stats();
	// print_flows();
}

int 
main(int argc, char *argv[]) {

	int ch;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
		switch (ch) {		
		case 'i':
			monitor_live_traffic(optarg);
			break;
		case 'r':
			monitor_offline_traffic(optarg);
			break;
		default:
			usage();
			break;
		}
	}

	// print_all_packets();
	printf("\n");

	argc -= optind;
	argv += optind;	
	
	return 0;
}