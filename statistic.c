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
#include "lists.h"

typedef int bool;
#define true 1
#define false 0


void loop_on_trace( char *fullname, struct pcap_pkthdr* header, const u_char *packet,
			   		pcap_t *pcap_handle, flowv4_record **flowv4_table, 
					flowv6_record **flowv6_table, int *icmp, flowv4_record* record, 
					uint64_t* nbr_pkts_out, uint64_t* nbr_pkts_in ,bool* found_bna_flow) {

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
	flowv4_record flow;
	flowv4_record* current;

	size_t index;


	while ((packet = pcap_next(pcap_handle, header))) {
		index = 0;
		ethernet_hdr = (struct ether_header*)packet;
		index += sizeof(struct ether_header);
		if (ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (struct ip*)(packet + index);	
			index += sizeof(struct ip);
			inet_ntop(AF_INET, &(ip_hdr->ip_src), sourceIp, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_hdr->ip_dst), destIp, INET_ADDRSTRLEN);

			// create flow to get key
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

					if((sourcePort == 2499 || destPort == 2499) && !(*found_bna_flow)){
						record->key.srcIp = flow.key.srcIp;
						record->key.destIp = flow.key.destIp;	
						record->key.ipProto = IPPROTO_TCP;
						record->key.srcPort = sourcePort;
						record->key.destPort = destPort;
						*found_bna_flow = true;
					}

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

				if (*found_bna_flow) {
				
					if (compare_outgoing(&flow, record)){
						*nbr_pkts_out += 1;				
					} else if (compare_incoming(&flow, record)){
						*nbr_pkts_in += 1;	
					}
				
				}

				current = existing_flowv4(flowv4_table, &flow);
				if (current == NULL) {
					flowv4_record* new_flow = create_flowv4_record(inet_addr(sourceIp), inet_addr(destIp),
								   									sourcePort, destPort, ip_hdr->ip_p, header->ts);	
					if (new_flow == NULL) {
						fprintf(stderr, "Couldn't create flow record");
						exit(EXIT_FAILURE);	
					}
					current = new_flow;
					add_flowv4(flowv4_table, new_flow);
				}

				uint16_t size;
				uint16_t wire_size;
				wire_size = ntohs(ip_hdr->ip_len) + 14;   // ETHERNET HEADER SIZE
				if (ip_hdr->ip_p == IPPROTO_TCP) {
					size = ntohs(ip_hdr->ip_len) - (tcp_hdr->doff * 4) - (ip_hdr->ip_hl * 4);
				} else if (ip_hdr->ip_p == IPPROTO_UDP) {
					size = ntohs(udp_hdr->len);	
				}
				update_stats(current, size, wire_size, header->ts);

			} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
				icmp_hdr = (struct icmphdr*)(packet + index);	
				index += sizeof(struct icmphdr);

				if (icmp_hdr->type != ICMP_TIMESTAMP && icmp_hdr->type != ICMP_TIMESTAMPREPLY) {
					*icmp += 1;	
				}
			}
		}

		// TODO IPV6

			
	
	}
	printf("End of the loop \n");
	
	pcap_close(pcap_handle);

}


int main(int argc, char **argv) {
	
	char *input_dir;
	char *filename;
	char *filename_ts;
	int c;

	while((c = getopt(argc, argv, "d:f:t:")) != -1){
		switch(c){
			case 'd':	
				input_dir = optarg;
				break;
			case 'f':
				filename = optarg;
				break;
			case 't':
				filename_ts = optarg;
				break;
			case '?':
				fprintf(stderr, "Unknown option");
				printf("Usage: statistic -d <name>\n");
				printf("-d: name of the directory containing the trace \n");
				printf("-f: name of the file to export the statistic\n");
				printf("-t: name of the file to export the timeseries\n");
				exit(EXIT_FAILURE);	
		}	
	}

	FILE *fptr;
	FILE *fsptr;

	fptr = fopen(filename, "w");
	fsptr = fopen(filename_ts, "w");

	if(fptr == NULL) {
		fprintf(stderr, "Error opening the statistic file");
		exit(EXIT_FAILURE);	
	}

	if(fsptr == NULL) {
		fprintf(stderr, "Error opening the timeserie file");
		exit(EXIT_FAILURE);	
	}

	List* timeseries_req = emptylist();
	List* timeseries_res = emptylist();


	flowv4_record bna_flow;
	flowv4_record *flowv4_table = NULL;
	flowv6_record *flowv6_table = NULL;

	bool found_bna_flow = false;
	uint64_t nbr_pkts_out = 0;
	uint64_t nbr_pkts_in = 0;
	int n;
	int icmp;
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
			loop_on_trace(fullname, &header, packet, pcap_handle, &flowv4_table,
						   					&flowv6_table, &icmp, &bna_flow, &nbr_pkts_out, &nbr_pkts_in,
											&found_bna_flow);	
			add(nbr_pkts_out, timeseries_req);
			add(nbr_pkts_in, timeseries_res);
			nbr_pkts_out = 0;
			nbr_pkts_in = 0;
			i++;
		}
		fprintf(fptr, "SIP\tDIP\tSPORT\tDPORT\tPROTO\tTGH\tAVG\tMAX\tTOTAL\tWIRE\t#PKTS\tFIRST\tLAST\tINTERARRIVAL\tDUR\n");
		export_allv4_to_file(&flowv4_table, fptr);	
		display_flowv4(&bna_flow, fsptr, true);	
		export_list_to_file(timeseries_req, fsptr);
		display_flowv4(&bna_flow, fsptr, false);
		export_list_to_file(timeseries_res, fsptr);
		free(fullname);
	
	} else {
		fprintf(stderr, "Could not open directory: %s\n", input_dir);
		exit(EXIT_FAILURE);	
	}

	while(n--) {
		free(namedlist[n]);	
	}

	clear_hash_recordv4(&flowv4_table);
	free(namedlist);
	destroy(timeseries_req);
	fclose(fptr);
	fclose(fsptr);
	return 0;
}
