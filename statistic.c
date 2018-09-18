#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "flows.h"


void loop_on_trace( char *fullname, struct pcap_pkthdr* header, const u_char *packet,
			   		pcap_t *pcap_handle, flowv4_record **flowv4_table, 
					flowv6_record **flowv6_table) {

	char errbuf[PCAP_ERRBUF_SIZE];

	printf("Opening input %s\n", fullname);
	pcap_handle = pcap_open_offline(fullname, errbuf);
	if (pcap_handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", fullname, errbuf);
		exit(EXIT_FAILURE);	
	}

	struct ether_header* ethernet_hdr;
	struct ip* ip_hdr;
	struct tcphdr* tcp_hdr;
	struct udphdr* udp_hdr;
	struct icmphdr* icmp_hdr;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;

	size_t index = 0;

	while ((packet = pcap_next(pcap_handle, header))) {
		ethernet_hdr = (struct ether_header*)packet;
		index += sizeof(struct ether_header);
		if (ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (struct ip*)(packet + index);	
			index += sizeof(struct ip);
			inet_ntop(AF_INET, &(ip_hdr->ip_src), sourceIp, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_hdr->ip_dst), destIp, INET_ADDRSTRLEN);

			// create flow to get key
			flowv4_record flow;
			memset(&flow, 0, sizeof(flowv4_record));
			
			flow.key.srcIp = inet_addr(sourceIp);
			flow.key.destIp = inet_addr(destIp);
			flow.key.ipProto = ip_hdr->ip_p;

			if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP) {
			
				if (ip_hdr->ip_p == IPPROTO_TCP) {
					tcp_hdr = (struct tcphdr*)(packet + index);	
					index += sizeof(struct tcphdr);
					sourcePort = ntohs(tcp_hdr->source);
					destPort = ntohs(tcp_hdr->dest);

					// Check in the hash table 
				}

				else if (ip_hdr->ip_p == IPPROTO_UDP) {
					udp_hdr = (struct udphdr*)(packet + index);
					index += sizeof(struct udphdr);
					sourcePort = ntohs(udp_hdr->source);
					destPort = ntohs(udp_hdr->dest);
				}

				flow.key.srcPort = sourcePort;
				flow.key.destPort = destPort;

				flowv4_record* check_exist = existing_flowv4(flowv4_table, &flow);
				if (check_exist == NULL) {
					flowv4_record* new_flow = create_flowv4_record(inet_addr(sourceIp), inet_addr(destIp), sourcePort, destPort, ip_hdr->ip_p);	
					if (new_flow == NULL) {
						exit(EXIT_FAILURE);	
					}

					add_flowv4(flowv4_table, new_flow);
				} else {
				
				}
			}
			
		
		}

		// TODO IPV6

			
	
	}
	
	pcap_close(pcap_handle);

	return 0;

}


int main(int argc, char **argv) {
	
	char *input_dir;
	int c;

	while((c = getopt(argc, argv, "d:")) != -1){
		switch(c){
			case 'd':	
				input_dir = optarg;
				break;
			case '?':
				fprintf(stderr, "Unknown option");
				printf("Usage: statistic -d <name>\n");
				printf("-d: name of the directory containing the trace \n");
				exit(EXIT_FAILURE);	
		}	
	
	}

	flowv4_record *flowv4_table = NULL;
	flowv6_record *flowv6_table = NULL;

	int n;
	struct dirent **namedlist;

	pcap_t *pcap_handle = NULL;
	struct pcap_pkthdr header;
	const u_char *packet = NULL;

	n = scandir(input_dir, &namedlist, NULL, alphasort);
	if (n > 0) {
		int i = 2;	
		char *fullname;
		fullname = malloc(strlen(input_dir) + strlen(namedlist[i]->d_name) + 2);
		if (fullname == NULL) {
			fprintf(stderr, "Could not allocate memory for the fullname");
			exit(EXIT_FAILURE);	
		}
		fullname[0] = '\0';
		strncat(fullname, input_dir, strlen(input_dir));
		strncat(fullname, "/", 1);
		strncat(fullname, namedlist[i]->d_name, strlen(namedlist[i]->d_name));
		while (i < n ) {
			memcpy(fullname + strlen(input_dir) + 1, namedlist[i]->d_name, strlen(namedlist[i]->d_name));
			loop_on_trace(fullname, &header, packet, pcap_handle, &flowv4_table, &flowv6_table);	
		}
		free(fullname);
	
	} else {
		fprintf(stderr, "Could not open directory: %s\n", input_dir);
		exit(EXIT_FAILURE);	
	}

	while(n--) {
		free(namedlist[n]);	
	}
	free(namedlist);
	return 0;
}
