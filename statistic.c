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

#define BNA_PORT 2499
#define BNA_IP "192.168.248.11"

bool compare_ip(char* ipaddr, char* src, char* dest){
	bool res = false;
	if (strncmp(ipaddr, src, INET_ADDRSTRLEN) == 0){
		res = true;	
	} else if (strncmp(ipaddr, src, INET_ADDRSTRLEN) == 0){
		res = true;			
	}
	return res;
}

void loop_on_trace( char *fullname, struct pcap_pkthdr* header, const u_char *packet,
			   		pcap_t *pcap_handle, flowv4_record **flowv4_table, 
					flowv6_record **flowv6_table, int *icmp, flowv4_record* record, 
					hourly_stats* h_stats ,bool* found_bna_flow, List** inter_arrival,
					char* target_addr, uint16_t target_port, int number_inter) {

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
	int out;

	//while ((packet = pcap_next(pcap_handle, header))) {
	while((out = pcap_next_ex(pcap_handle, &header, &packet)) == 1){
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

					if((sourcePort == target_port || destPort == target_port) &&
								   	 compare_ip(target_addr, sourceIp, destIp) && 
									!(*found_bna_flow)){
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
						h_stats->pkt_out += 1;				
					} else if (compare_incoming(&flow, record)){
						h_stats->pkt_in += 1;	
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

					if (ip_hdr->ip_p == IPPROTO_TCP) {
						h_stats->tcp_nbr += 1;		
						if (sourcePort == target_port || destPort == target_port) {
										 
							h_stats->bna_nbr += 1;	
						} 
					} else if (ip_hdr->ip_p == IPPROTO_UDP) {
						h_stats->udp_nbr += 1;	
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

				if (*found_bna_flow) {
					if (compare_outgoing(&flow, record)) {
						h_stats->bytes_out += size;	
						if((*inter_arrival)->length < number_inter){
							add(compute_inter_arrival(&(header->ts), &(current->last_seen)), *inter_arrival);
						}
					} else if (compare_incoming(&flow, record)) {
						h_stats->bytes_in += size;	
					}	
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
	switch(out){
		case -1:
			fprintf(stderr, "Error reading file %s:%s\n",fullname, pcap_geterr(pcap_handle));	
			exit(EXIT_FAILURE);
		case -2:
			printf("End of file success\n");
	}
	pcap_close(pcap_handle);
}


int main(int argc, char **argv) {
	
	char *input_dir;
	char *filename;
	char *filename_ts;
	char *filename_conn;
	char *target_addr;
	uint16_t target_port = BNA_PORT;
	int c;
	int number_inter = 60;

	while((c = getopt(argc, argv, "d:f:t:c:a:p:n:")) != -1){
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
			case 'c':
				filename_conn = optarg;
				break;	
			case 'a':
				target_addr = optarg;
				break;
			case 'p':
				target_port = atoi(optarg);
				break;
			case 'n':
				number_inter = atoi(optarg);
				break;
			case '?':
				fprintf(stderr, "Unknown option");
				printf("Usage: statistic -d <name>\n");
				printf("-d: name of the directory containing the trace \n");
				printf("-f: name of the file to export the statistic\n");
				printf("-t: name of the file to export the timeseries\n");
				printf("-a: targeted ip address for statistics\n");
				printf("-p: targeted port for statistics\n");
				printf("-n: number of packet in list containing inter-packet times\n");
				exit(EXIT_FAILURE);	
		}	
	}

	FILE *fptr;
	FILE *fsptr;
	FILE *fptr_conn;

	fptr = fopen(filename, "w");
	fsptr = fopen(filename_ts, "w");
	fptr_conn = fopen(filename_conn, "w");

	if(fptr == NULL) {
		fprintf(stderr, "Error opening the statistic file");
		exit(EXIT_FAILURE);	
	}

	if(fsptr == NULL) {
		fprintf(stderr, "Error opening the timeserie file");
		exit(EXIT_FAILURE);	
	}

	// List of the number packets
	List* timeseries_pkt_req = emptylist();
	List* timeseries_pkt_res = emptylist();


	// List of the number bytes exchanged
	List* timeseries_byte_req = emptylist();
	List* timeseries_byte_res = emptylist();	

	// List of interarrival
	List* inter_arrival = emptylist();

	// List of connections (UDP, TCP)
	List* udp_conn = emptylist();
	List* tcp_conn = emptylist();
	List* bna_conn = emptylist();

	flowv4_record bna_flow;
	flowv4_record *flowv4_table = NULL;
	flowv6_record *flowv6_table = NULL;

	bool found_bna_flow = false;

	hourly_stats* h_stats = init_hourly_stats();

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
						   					&flowv6_table, &icmp, &bna_flow, h_stats, 
											&found_bna_flow, &inter_arrival, target_addr, target_port, number_inter);	
			add(h_stats->pkt_out, timeseries_pkt_req);
			add(h_stats->pkt_in, timeseries_pkt_res);
			add(h_stats->bytes_out, timeseries_byte_req);
			add(h_stats->bytes_in, timeseries_byte_res);
			add(h_stats->tcp_nbr, tcp_conn);
			add(h_stats->udp_nbr, udp_conn);
			add(h_stats->bna_nbr, bna_conn);
			reset_hourly_stats(h_stats);
			i++;
		}
		fprintf(fptr, "SIP\tDIP\tSPORT\tDPORT\tPROTO\tTGH\tAVG\tMAX\tTOTAL\tWIRE\t#PKTS\tFIRST\tLAST\tINTERARRIVAL\tDUR\n");
		export_allv4_to_file(&flowv4_table, fptr);	
		display_flowv4(&bna_flow, fsptr, true);	
		export_list_to_file(timeseries_pkt_req, fsptr);
		export_list_to_file(timeseries_byte_req, fsptr);
		export_list_to_file(inter_arrival, fsptr);
		display_flowv4(&bna_flow, fsptr, false);
		export_list_to_file(timeseries_pkt_res, fsptr);
		export_list_to_file(timeseries_byte_res, fsptr);
		fprintf(fptr_conn, "TCP\n");
		export_list_to_file(tcp_conn, fptr_conn);
		fprintf(fptr_conn, "UDP\n");
		export_list_to_file(udp_conn, fptr_conn);
		fprintf(fptr_conn, "BNA\n");
		export_list_to_file(bna_conn, fptr_conn);
		free(fullname);
	
	} else {
		fprintf(stderr, "Could not open directory: %s\n", input_dir);
		exit(EXIT_FAILURE);	
	}

	while(n--) {
		free(namedlist[n]);	
	}

	clear_hash_recordv4(&flowv4_table);
	destroy_hourly_stats(h_stats);
	free(namedlist);
	destroy(timeseries_pkt_req);
	destroy(timeseries_pkt_res);
	destroy(timeseries_byte_req);
	destroy(timeseries_byte_res);
	destroy(inter_arrival);
	destroy(tcp_conn);
	destroy(udp_conn);
	destroy(bna_conn);
	fclose(fptr);
	fclose(fsptr);
	fclose(fptr_conn);
	return 0;
}
