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
#include <linux/icmp.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

void create_new_trace(char* name, FILE *fptr){

}

void copy_packet(struct pcap_pkthdr *header, const u_char* packet, pcap_dumper_t *pdumper){
	pcap_dump((u_char*) pdumper, header, packet);	
}



void add_one_hour(struct timeval *start, struct timeval *stop){
	struct timeval tv;
	memcpy(stop, start, sizeof(struct timeval));

	tv.tv_sec = 3600;
	tv.tv_usec = 0;
	timeradd(start, &tv, stop);
}

void change_filename(struct timeval *stop, char **output_file){
	time_t time;
	struct tm *tm;
	time = stop->tv_sec;	
	tm = localtime(&time);
	char datebuf[16];

	strftime(datebuf, 19, "%Y-%m-%d:%H:%M:%S", tm);
	snprintf(*output_file, 30, "%s_shut1.pcap", datebuf);

} 

void split_file(char* input_file, char** output_file, struct timeval *start,
			   	struct timeval *stop, struct pcap_pkthdr* header,
			   	const u_char *packet, pcap_t *handle, char **state) {

	char errbuf[PCAP_ERRBUF_SIZE];

	if (strncmp(*state, "NEW", 3) == 0) {
		handle = pcap_open_offline(input_file, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open pcap file %s: %s\n", input_file, errbuf);	
			exit(EXIT_FAILURE);
		}				
		*state = "WIP";
	} 

	pcap_t *pd;
	pcap_dumper_t *pdumper;
	pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (pd == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", *output_file, errbuf);
		exit(EXIT_FAILURE);	
	}

	
	if (access ( *output_file, F_OK) != -1) {
		pdumper = pcap_dump_open_append(pd, *output_file);	
	} else {
		pdumper = pcap_dump_open(pd, *output_file);
	}
	if (pdumper == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", *output_file, errbuf);	
		exit(EXIT_FAILURE);
	}

	while ((packet = pcap_next(handle, header))) {
		if (start == NULL) {
	
			memcpy(start, &(header->ts), sizeof(struct timeval));	
			add_one_hour(start, stop);
		}

		if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, <)) {

			copy_packet(header, packet, pdumper);						

		} else if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, =)) {
			
			copy_packet(header, packet, pdumper);						
			memcpy(start, stop, sizeof(struct timeval));
			add_one_hour(start, stop);
			pcap_close(pd);
			pcap_dump_close(pdumper);
			return;

		} else if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, >)) {

			pcap_close(pd);
			pcap_dump_close(pdumper);
			memcpy(stop, start, sizeof(struct timeval));
			add_one_hour(start, stop);
		}
			
	}

	pcap_close(handle);
	*state = "NEW";
}

int main(int argc, char **argv) {

	char *comd_dir_in;
	char *comd_dir_out;
	char *start_date;

	int c;

	while ((c = getopt(argc, argv, "i:o:f:")) != -1){
		switch(c){
			case 'i':
				comd_dir_in = optarg;
				break;
			case 'o':
				comd_dir_out = optarg;
				break;

			case 'f':
				start_date = optarg;
				break;
				
			case '?':
				fprintf(stderr, "Unknown option");
				printf("Usage: timpesplit -d <name> -e <name> -o <name> -r <name>\n");
				printf("i: name directory containing the shuttle1 capture\n");
				printf("o: output directory hof shuttle2\n");
				printf("f: name of the first file\n");
				exit(EXIT_FAILURE);
		}	
	}


	DIR *dptr_in;
	struct dirent *dir_in;	
	
	struct timeval *start = NULL;	
	struct timeval *stop = NULL;


	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;

	char** output_file = &start_date;
	char* state = "NEW";

	dptr_in = opendir(comd_dir_in);
	if (dptr_in !=NULL) {
		while ( dir_in = readdir(dptr_in)) {
				
			split_file(dir_in->d_name, output_file, start, stop, &header,packet, handle, &state);	
		}
					
	} else {
		fprintf(stderr,"Could not open direcotry: %s\n", comd_dir_in);	
		exit(EXIT_FAILURE);
	}

	return 0;
}
