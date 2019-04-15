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

typedef int bool;
#define true 1
#define false 0


bool compare_ip(char* ipaddr, char* src, char* dest){
    bool res = (strncmp(ipaddr, src, INET_ADDRSTRLEN) == 0 || 
                strncmp(ipaddr, dest, INET_ADDRSTRLEN) == 0);

    return res;
}

void get_time_frame_limit(struct timeval **start, struct timeval **stop, u_int frame_size){
    struct timeval tv;
    tv.tv_sec = frame_size;
    tv.tv_usec = 0;
    timeradd(*start, &tv, *stop);

}

void change_filename(struct timeval *stop, char* prefix, char **output_file, bool binary){
    time_t time;
    struct tm *tm;
    time = stop->tv_sec;
    tm = localtime(&time);
    char datebuf[16];

    strftime(datebuf, 19, "%Y-%m-%d:%H:%M", tm);

    char * fullname;
    size_t fullsize = strlen(prefix) + strlen(datebuf) + 2;

    fullname = malloc(fullsize);
    if (fullname == NULL){
        fprintf(stderr, "Could not allocate memory for the fullname");
        exit(EXIT_FAILURE);
    }
    fullname[0] = '\0';
    strncat(fullname, prefix, strlen(prefix));
    strncat(fullname, "/", 1);
    strncat(fullname, datebuf, strlen(datebuf));

    if(binary){
        snprintf(*output_file, fullsize + 4, "%s.bin", fullname);
    } else {
        snprintf(*output_file, fullsize + 4, "%s.txt", fullname); 
    }

    free(fullname);
}

void loop_on_trace(char* fullname, struct pcap_pkthdr* header, const u_char *packet,
                   pcap_t *pcap_handle, flowv4_record **flowv4_table,
                   struct timeval *start, struct timeval *stop,
                   unsigned int frame_size, char **output_file, char *output_prefix,
                   char** text_output_file, char *text_output_prefix){

    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Opening input %s\n", fullname);
    pcap_handle = pcap_open_offline(fullname, errbuf);
    if(pcap_handle == NULL){
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

    // Time frame computation
    struct timeval tv;
    tv.tv_sec = frame_size;
    tv.tv_usec = 0;

    while((out = pcap_next_ex(pcap_handle, &header, &packet)) == 1){
        if(start->tv_sec == 0){

            start->tv_sec = header->ts.tv_sec;
            stop->tv_sec = start->tv_sec;
            timeradd(start, &tv, stop);
            stop->tv_usec = 999999;
            change_filename(start, output_prefix, output_file, true);
            change_filename(start, text_output_prefix, text_output_file, false);
        }

        if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, <=)){
            // Do nothing  if in time frame
        } else if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, >)){
            // Create new file and re-initialized
            FILE *fptr;
            FILE *tfptr;

            fptr = fopen(*output_file, "wb");
            if (fptr == NULL){
                fprintf(stderr, "Error opening the binary output file: %s\n", *output_file);
                exit(EXIT_FAILURE);
            }
            printf("Exporting to file %s \n", *output_file);
            export_binary_allv4_to_file(flowv4_table, fptr);
            fclose(fptr);
            change_filename(stop, output_prefix, output_file, true);
            if (text_output_file != NULL){
                tfptr = fopen(*text_output_file, "w");
                if(tfptr == NULL){
                    fprintf(stderr, "Error opening the text output file: %s\n", *text_output_file);
                    exit(EXIT_FAILURE);
                }
                fprintf(tfptr, "SIP\tDIP\tSPORT\tDPORT\tPROTO\tSIZE\t#PKTS\tFIRST\tLAST\tDUR\n");
                printf("Exporting to file %s \n", *text_output_file);
                export_allv4_to_file(flowv4_table, tfptr);
                change_filename(stop, text_output_prefix, text_output_file, false);
                fclose(tfptr);
            }

            start->tv_sec = stop->tv_sec;
            timeradd(start, &tv, stop);
            stop->tv_usec = 999999;
            clear_hash_recordv4(flowv4_table);
            *flowv4_table = NULL;
        }

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
				//uint16_t wire_size;
				//wire_size = ntohs(ip_hdr->ip_len) + 14;   // ETHERNET HEADER SIZE
				if (ip_hdr->ip_p == IPPROTO_TCP) {
					size = ntohs(ip_hdr->ip_len) - (tcp_hdr->doff * 4) - (ip_hdr->ip_hl * 4);
				} else if (ip_hdr->ip_p == IPPROTO_UDP) {
					size = ntohs(udp_hdr->len) - 8;	// minus UDP header

				}

                if (size > 0) {
                
				    update_stats(current, size, header->ts);
                
                }

			} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
				icmp_hdr = (struct icmphdr*)(packet + index);	
				index += sizeof(struct icmphdr);

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

void help(){
    printf("Usage: flowextractor -d <name> -o <name>\n");
    printf("-d: name of the directory containing the trace \n");
    printf("-o: name of the file to output the binary version of flow\n");
    printf("-t: name of the file to output text version of the flow\n");
    printf("-s: size of the time frame in second\n");
}

int main(int argc, char **argv){

    char *input_dir = NULL;
    char *text_output_prefix = NULL;
    char *output_prefix = NULL;
    int c;

    unsigned int frame_size = 0;

    while((c = getopt(argc, argv, "d:o:t:s:h")) != -1){
        switch(c){
            case 'd':
                input_dir = optarg;
                break;
            case 'o':
                output_prefix = optarg;
                break;
            case 't':
                text_output_prefix = optarg;
                break;
            case 's':
                frame_size = atoi(optarg);
                break;
            case 'h':
                help();
                exit(EXIT_FAILURE);
            case '?':
                fprintf(stderr, "Unknown option");
                help();
                exit(EXIT_FAILURE);
        }
   
    }

    if (output_prefix == NULL){
        fprintf(stderr, "No name for the ouput"); 
        exit(EXIT_FAILURE);
    }
    // Len(prefix) + (date format size) + / and \0 + file suffix .bin
    char *rotate_name = (char *) malloc(strlen(output_prefix) + 16 + 2 + 4);
    if (rotate_name == NULL){
        fprintf(stderr, "Could not allocate rotate_name");
        exit(EXIT_FAILURE);
    }

    char **output_file = &rotate_name;

    char **text_output_file = (char**) NULL;

    char *rotate_text_name = (char*) malloc(strlen(text_output_prefix) + 16 + 2 + 4);

    if(rotate_text_name == NULL){
        fprintf(stderr, "Could not allocate rotate_text_name");
        exit(EXIT_FAILURE);
    }

    if (text_output_prefix != NULL){
        text_output_file = &rotate_text_name;
    } else{
        free(rotate_text_name);
    }

    if (frame_size == 0){
        fprintf(stderr, "Size must be nonzero");
        exit(EXIT_FAILURE);
    }

    flowv4_record *flowv4_table = NULL;
    
    int n;
    struct dirent **namedlist;

    pcap_t *pcap_handle = NULL;
    struct pcap_pkthdr header;
    const u_char *packet = NULL;

    struct timeval start;
    start.tv_sec = 0;
    start.tv_usec = 0;

    struct timeval stop;
    stop.tv_sec = 0;
    stop.tv_usec = 0;

    n = scandir(input_dir, &namedlist, NULL, alphasort);
    if(n > 0){
        int i = 2; // not taking parent directory '..' and current directory '.' 
        char *fullname;
        fullname = malloc(strlen(input_dir) + strlen(namedlist[i]->d_name) + 2);

        if(fullname == NULL){ 
            fprintf(stderr, "Could not allocate memory for the fullname");
            exit(EXIT_FAILURE);
        }

        fullname[0] = '\0';
        strncat(fullname, input_dir, strlen(input_dir));
        strncat(fullname, "/", 1);
        strncat(fullname, namedlist[i]->d_name, strlen(namedlist[i]->d_name));

        while(i < n){
            memcpy(fullname + strlen(input_dir) + 1, namedlist[i]->d_name, strlen(namedlist[i]->d_name));
            loop_on_trace(fullname, &header, packet, pcap_handle, &flowv4_table, &start, &stop, frame_size,
                    output_file, output_prefix, text_output_file, text_output_prefix);
            i++; 
        }

        FILE *fptr;
        FILE *tfptr;
        fptr = fopen(*output_file, "wb");
        if (fptr == NULL){
            fprintf(stderr, "Error opening the binary output file: %s\n", *output_file);
            exit(EXIT_FAILURE);
        }
        printf("Exporting to file %s \n", *output_file);
        export_binary_allv4_to_file(&flowv4_table, fptr);
        fclose(fptr);

        if (text_output_file != NULL){
            tfptr = fopen(*text_output_file, "w");
            if(tfptr == NULL){
                fprintf(stderr, "Error on opening the text output file: %s\n", *text_output_file); 
                exit(EXIT_FAILURE);
            }
            fprintf(tfptr, "SIP\tDIP\tSPORT\tDPORT\tPROTO\tSIZE\t#PKTS\tFIRST\tLAST\tDUR\n");
            printf("Exporting to file %s \n", *text_output_file);
            export_allv4_to_file(&flowv4_table, tfptr);
            fclose(tfptr);
        }
        clear_hash_recordv4(&flowv4_table);
        flowv4_table = NULL;

        free(fullname);
    
    } else {
        fprintf(stderr, "Could not open directory: %s\n", input_dir);
        exit(EXIT_FAILURE);
    }

    while(n--){
        free(namedlist[n]); 
    }

    clear_hash_recordv4(&flowv4_table);
    free(namedlist);
    free(rotate_name);
    if (text_output_prefix != NULL){
        free(rotate_text_name);
    }
    return 0;
}
