#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

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
	
	if (argc < 2) { 
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

	fptr = fopen(argv[2], "r");
	if (fptr == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", argv[2], errbuf);	
			exit(EXIT_FAILURE); 
	}

	while ((read = getline(&line, &len, fptr)) != -1) {
		parse_line(line, read, &begin, &end, &offset);
		printf("Begin: %d, End: %d, Offset: %f\n", begin, end, offset);
	}
	
	while ((packet = pcap_next(handle,&header))) { 
	
			packet_counter++;
	
	} 
	pcap_close(handle);
	fclose(fptr);	
	
	printf("%d\n", packet_counter);
	return 0;
}
