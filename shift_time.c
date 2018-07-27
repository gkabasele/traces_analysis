#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

void parse_line(char *line, ssize_t len ,int *begin, int *end, float *offset) {

	char current_char;
	char * subset;
	int j = 0;	

	char step = 'd';

	for (int i = 0; i < len; i++) {
		current_char = line[i];	
		if (current_char == ',' || current_char == '\n') {
			subset = malloc(((i-1) - j)* sizeof(char));

			if (subset == NULL) {
				fprintf(stderr, "Could not allocate memory\n");
				exit(EXIT_FAILURE);
			}

			for (int s = 0; j <= i-1; s++) {
				subset[s] = line[j];	
				j++;
			}

			if (step == 'd') {
				*begin = atoi(subset);	
				step = 'b';
			} else if (step == 'b') {
				*end = atoi(subset);
				step = 'e';
			
			} else if (step == 'e') {
				*offset = atof(subset);
			} else {
				fprintf(stderr, "Unknown step when parsing line \n");
				exit(EXIT_FAILURE);
			}
			
			free(subset);	
			j = i+1;
			
		}
	}
}

void change_pkt_offset(struct pcap_pkthdr *header, const u_char* packet, float offset, pcap_dumper_t *pdumper) {

	struct pcap_pkthdr new_header;

	struct pcap_pkthdr *ptr = &new_header;

	memcpy(ptr, header, sizeof(struct pcap_pkthdr));

	(&(ptr->ts))->tv_usec += offset*1000; //millisecond to microsecond
	pcap_dump((u_char*) pdumper, &new_header, packet);

}

int main(int argc, char **argv) {

	unsigned int packet_counter=0;
	struct pcap_pkthdr header; 
	const u_char *packet;

	FILE *fptr;
	char* line = NULL;
	size_t len = 0;
	ssize_t read;

	int begin = 0;
	int end = 0;
	float offset = 0;
	
	if (argc < 4) { 
		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]); 
		exit(EXIT_FAILURE); 
	} 
	
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE];  
	handle = pcap_open_offline(argv[1], errbuf); 
	
	if (handle == NULL) { 
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
		exit(EXIT_FAILURE); 
	}

	pcap_t *pd;
	pcap_dumper_t *pdumper;
	pd = pcap_open_dead(DLT_EN10MB, 65535);	

	if (pd == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[3], errbuf);	
		exit(EXIT_FAILURE);
	}

	pdumper = pcap_dump_open(pd, argv[3]);

	if (pdumper == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[3], errbuf);	
		exit(EXIT_FAILURE);
	}
	

	fptr = fopen(argv[2], "r");
	if (fptr == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", argv[2], errbuf);	
		exit(EXIT_FAILURE); 
	}

	//while ((read = getline(&line, &len, fptr)) != -1) {
	//	parse_line(line, read, &begin, &end, &offset);
	//	printf("Begin: %d, End: %d, Offset: %f\n", begin, end, offset);
	//}

	read = getline(&line, &len, fptr);			
	parse_line(line, read, &begin, &end, &offset);
	
	
	while ((packet = pcap_next(handle,&header))) { 
		change_pkt_offset(&header, packet, offset, pdumper);
		if (packet_counter == end) {
			read = getline(&line, &len, fptr);
			parse_line(line, read, &begin, &end, &offset);
		}	
	
		packet_counter++;
	
	} 
	pcap_close(handle);
	pcap_close(pd);
	pcap_dump_close(pdumper);
	fclose(fptr);	
	
	printf("%d\n", packet_counter);
	return 0;
}
