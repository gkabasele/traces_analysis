#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "array.h"


#define CAPACITY 6000

// i is the current index in the lookup table
float interp( interp_array_t *c, int x, int i) {

	if ( c->array[i].x <= x && c->array[i+1].x >= x ) {
		float diffx = x - c->array[i].x;
		float diffn = c->array[i+1].x - c->array[i].x;

		return c->array[i].y + ( c->array[i+1].y - c->array[i].y ) * diffx / diffn; 
	}

	return 0; // Not in Range
}


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


void add_to_lookup(interp_array_t *a, int begin_a, int begin_b, int end_a, int end_b, float offset_a, float offset_b) {
	
	// get index of the packet in the middle of the range between the two icmp offset
	int index = begin_a + ((begin_b - begin_a)/2);	
	float new_offset = offset_a + ((offset_b - offset_a)/2);
	add_array(a, index, new_offset);
	add_array(a, begin_b, offset_b);
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

	int begin_b = begin;
	int end_b = end;
	float offset_b = offset;
	
	//interp table
	interp_array_t array;
	interp_array_t* array_ptr = &array;
	int index = 0;
	float last_computed;

	init_array(array_ptr, CAPACITY); 
	
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

	read = getline(&line, &len, fptr);			
	parse_line(line, read, &begin, &end, &offset);
	add_array(array_ptr, begin, offset);
	
	while ((read = getline(&line, &len, fptr)) != -1) {
		begin_b = begin;
		end_b = end;
		offset_b = offset;
		parse_line(line, read, &begin, &end, &offset);	
		add_to_lookup(array_ptr, begin, begin_b, end, end_b, offset, offset_b);
	}

	add_array(array_ptr, end, offset);
	
	while ((packet = pcap_next(handle,&header))) { 
		int x0 = array_ptr->array[index].x;
		float y0 = array_ptr->array[index].y;

		if (index < array_ptr->size) {
			int x1 = array_ptr->array[index+1].x; 
			float y1 = array_ptr->array[index+1].y;

			if (packet_counter == x0) {
				change_pkt_offset(&header, packet, y0, pdumper);	
				last_computed = y0;
			} else if (packet_counter > x0 && packet_counter < x1) {
				float res = last_computed + ((y1 - last_computed)/(x1 - (packet_counter-1))); //*(x - x0)
				change_pkt_offset(&header, packet, res, pdumper);
				last_computed = res;
			} else if (packet_counter == x1){
				change_pkt_offset(&header, packet, y1, pdumper);
				last_computed = y1;
				index++;	
			}
		} else {
				change_pkt_offset(&header, packet, y0, pdumper);	
		}
		packet_counter++;
	} 

	pcap_close(handle);
	pcap_close(pd);
	pcap_dump_close(pdumper);
	fclose(fptr);	
	destroy_array(array_ptr);
	
	return 0;
}
