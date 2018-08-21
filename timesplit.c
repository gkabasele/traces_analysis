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



void add_one_hour(struct timeval **start, struct timeval **stop){

	struct timeval tv;
	tv.tv_sec = 3600;
	tv.tv_usec = 0;
	timeradd(*start, &tv, *stop);
}

void change_filename(struct timeval *stop, char **output_file){

	time_t time;
	struct tm *tm;
	time = stop->tv_sec;	
	tm = localtime(&time);
	char datebuf[16];

	strftime(datebuf, 19, "%Y-%m-%d:%H:%M", tm);
	snprintf(*output_file, 30, "%s_shut2.pcap", datebuf);

} 

void split_file(char* input_file, char** output_file, struct timeval *start,
			   	struct timeval *stop, struct pcap_pkthdr* header,
			   	const u_char *packet, pcap_t *handle, int *index){
				

	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct timeval tv;
	tv.tv_sec = 3600;
	tv.tv_usec = 0;

	printf("Opening input %s\n", input_file);
	handle = pcap_open_offline(input_file, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", input_file, errbuf);	
		exit(EXIT_FAILURE);
	}				

	pcap_t *pd;
	pcap_dumper_t *pdumper;
	pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (pd == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", *output_file, errbuf);
		exit(EXIT_FAILURE);	
	}

	
	if (access ( *output_file, F_OK) != -1) {
		printf("File %s already exist, reopen it \n", *output_file);
		pdumper = pcap_dump_open_append(pd, *output_file);	
	} else {
		printf("File %s does not exist, creating it\n", *output_file);
		pdumper = pcap_dump_open(pd, *output_file);
	}
	if (pdumper == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", *output_file, errbuf);	
		exit(EXIT_FAILURE);
	}

	while ((packet = pcap_next(handle, header))) {

		if (start-> tv_sec == 0) {

			start->tv_sec = header->ts.tv_sec;	
			stop->tv_sec = start->tv_sec;
			timeradd(start, &tv, stop);
			stop->tv_usec = 999999;
		}

		if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, <=)) {

			copy_packet(header, packet, pdumper);						

		} else if (timercmp(&(header->ts), start, >) && timercmp(&(header->ts), stop, >)) {

			start->tv_sec = stop->tv_sec;
			change_filename(stop, output_file);
			timeradd(start, &tv, stop);
			stop->tv_usec = 999999;
			pcap_close(pd);
			pcap_dump_close(pdumper);
			pcap_close(handle);
			return;
		}
			
	}

	pcap_close(pd);
	pcap_dump_close(pdumper);
	pcap_close(handle);
	*index += 1;
}

int main(int argc, char **argv) {

	char *comd_dir_in;
	char *start_date;

	int c;

	while ((c = getopt(argc, argv, "i:f:")) != -1){
		switch(c){
			case 'i':
				comd_dir_in = optarg;
				break;
			case 'f':
				start_date = optarg;
				break;
			case '?':
				fprintf(stderr, "Unknown option");
				printf("Usage: timpesplit -i <name> -f <name>\n");
				printf("i: name directory containing the shuttle1 capture\n");
				printf("f: name of the first file\n");
				exit(EXIT_FAILURE);
		}	
	}


	int n;
	struct dirent **namedlist;
	
	struct timeval start; 	
	start.tv_sec = 0;
	start.tv_usec = 0;

	struct timeval stop ;
	stop.tv_sec = 0;
	stop.tv_usec = 0;	


	pcap_t *handle = NULL;
	struct pcap_pkthdr header;
	const u_char *packet = NULL;

	char** output_file = &start_date;

	n = scandir(comd_dir_in, &namedlist, NULL, alphasort);
	if (n > 0) {
		int i = 2;
		char *full_name;
		full_name = malloc(strlen(comd_dir_in) + strlen(namedlist[i]->d_name) + 2);
		if (full_name == NULL) {
			fprintf(stderr, "Could not allocate memory for the fullname");	
			exit(EXIT_FAILURE);
		}
		full_name[0] = '\0';
		strncat(full_name, comd_dir_in, strlen(comd_dir_in));
		strncat(full_name, "/", 1);
		strncat(full_name, namedlist[i]->d_name, strlen(namedlist[i]->d_name));
		while (i < n) {
			memcpy(full_name+strlen(comd_dir_in)+1, namedlist[i]->d_name, strlen(namedlist[i]->d_name));
			split_file(full_name, output_file, &start, &stop, &header,packet, handle, &i);	
		}	
		free(full_name);

	} else {
		fprintf(stderr,"Could not open direcotry: %s\n", comd_dir_in);	
		exit(EXIT_FAILURE);
	}

	while(n--) {
		free(namedlist[n]);	
	}
	free(namedlist);

	return 0;
}
