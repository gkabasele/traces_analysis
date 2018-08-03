#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include "array.h"


#define CAPACITY 8000

int debug = 0;

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

/*
 * In this strategy, we add points between existing points:
 * x	y
 * 1	2
 * 5	3
 * becomes
 * x	y
 * 1	2
 * 3	2,5
 * 5	3
 */
void add_to_lookup_middle(interp_array_t *a, int begin_a, int begin_b, int end_a, int end_b, float offset_a, float offset_b, int nbr_pivot) {


	int i = 1;

	while (i < nbr_pivot) {
		// get index of the packet in the middle of the range between the two icmp offset
		int index = begin_a + ((begin_b - begin_a) * ((float)i/nbr_pivot));
		float new_offset = offset_a + ((offset_b - offset_a) * ((float)i/nbr_pivot));
		add_array(a, index, new_offset);
		i++;
	}

	add_array(a, begin_b, offset_b);
}

void add_to_lookup_step(interp_array_t *a, int begin_a, int begin_b, int end_a, int end_b, float offset_a, float offset_b) {

	add_array(a, begin_b, offset_b);
}

void change_pkt_offset(struct pcap_pkthdr *header, const u_char* packet, float offset, pcap_dumper_t *pdumper) {

	struct pcap_pkthdr new_header;
	struct pcap_pkthdr *ptr = &new_header;
	memcpy(ptr, header, sizeof(struct pcap_pkthdr));
	(&(ptr->ts))->tv_usec += offset*1000; //millisecond to microsecond
	pcap_dump((u_char*) pdumper, &new_header, packet);
}

void step_strategy(interp_array_t *array_ptr, int packet_counter, int *index, pcap_dumper_t *pdumper, const u_char *packet, struct pcap_pkthdr *header) {

	int x0 = array_ptr->array[*index].x;
	float y0 = array_ptr->array[*index].y;

	if (*index < array_ptr->size) {
		int x1 = array_ptr->array[*index+1].x;
		float y1 = array_ptr->array[*index+1].y;
		float step = (float)((y1-y0)/(x1-x0));
		float res;

		if (packet_counter == x0) {
			res = y0;
		} else if (packet_counter > x0 && packet_counter < x1) {
			res = y0 + (packet_counter - x0) * step;
		} else if (packet_counter == x1) {
			res = y1;
			*index += 1 ;
		}

		if (debug != 1) {
			change_pkt_offset(header, packet, res, pdumper);
		}
		
		if (debug == 1 && packet_counter >= 37401 && packet_counter <= 37503) {
			printf("Packet Nbr: %d -> %f\n", packet_counter, res);	
		}

	} else {
			change_pkt_offset(header, packet, y0, pdumper);
	}
}


void piecewise_strategy(interp_array_t *array_ptr, int packet_counter, int *index, pcap_dumper_t *pdumper, const u_char *packet, struct pcap_pkthdr *header){

	int x0 = array_ptr->array[*index].x;
	float y0 = array_ptr->array[*index].y;

	if (*index < array_ptr->size) {
		int x1 = array_ptr->array[*index+1].x;
		float y1 = array_ptr->array[*index+1].y;
		float res;


		int dist_x1 = x1 - packet_counter;
		int dist_x0 = packet_counter - x0;

		if (dist_x0 <= dist_x1) {
			res = y0;	
		} else {
			res = y1;	
		}

		if (packet_counter == x1) {
			*index += 1;	
		}

		if (debug != 1) {
			change_pkt_offset(header, packet, res, pdumper);
		}

		if (debug == 1 && packet_counter >= 2673 && packet_counter <= 2731) {
			printf("Packet Nbr: %d -> %f\n", packet_counter, res);	
		}

	} else {
		change_pkt_offset(header, packet, y0, pdumper);
	}

}

void middle_strategy(interp_array_t *array_ptr, int packet_counter, float *last_computed, int *index, pcap_dumper_t *pdumper, const u_char *packet, struct pcap_pkthdr *header){

	int x0 = array_ptr->array[*index].x;
	float y0 = array_ptr->array[*index].y;

	if (*index < array_ptr->size) {
		int x1 = array_ptr->array[*index+1].x;
		float y1 = array_ptr->array[*index+1].y;
		float res;

		if (packet_counter == x0) {
			res = y0;
		} else if (packet_counter > x0 && packet_counter < x1) {
			res = *last_computed + ((y1 - *last_computed)/(x1 - (packet_counter-1))); //*(x - x0)
			*last_computed = res;
		} else if (packet_counter == x1) {
			res = y1;
			*index += 1;
		}

		if (debug != 1) {
			change_pkt_offset(header, packet, res, pdumper);
			*last_computed = res;
		}

		if (debug == 1 && packet_counter >= 2673 && packet_counter <= 2731) {
			printf("Packet Nbr: %d -> %f\n", packet_counter, res);	
		}

	} else {
		change_pkt_offset(header, packet, y0, pdumper);
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

	int begin_b = begin;
	int end_b = end;
   	float offset_b = offset;
	//interp table
	interp_array_t array;
	interp_array_t* array_ptr = &array;
	int index = 0;
	float last_computed;


	int c;
	char *input_file;
	char *output_file;
	char *offset_file;
	char *strategy;
	int nbr_pivot = 2;
	while((c = getopt(argc, argv, "i:o:f:s:n:d")) !=  -1){
		switch (c) {
			case 'i':
				input_file = optarg;
				break;
			case 'o':
				output_file = optarg;
				break;
			case 'f':
				offset_file = optarg;
				break;
			case 's':
				strategy = optarg;
				break;
			case 'n':
				nbr_pivot = atoi(optarg);
				break;
			case 'd':
				debug = 1;
				break;
			case '?':
				fprintf(stderr, "Unknown option");
				printf("USAGE: shift_time -i <name> -o <name> -f <name> -s <letter> \n");
				printf("i: name of input file containing the capture\n");
				printf("o: name of output file containing the capture\n");
				printf("f: name of the file containing the offset\n");
				printf("s: interpolation strategy\n");
				printf("n; number of pivot in the middle strategy interpolation\n");
				exit(EXIT_FAILURE);
		}
	}

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(input_file, errbuf);
	if (handle == NULL) {
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", input_file, errbuf);
		exit(EXIT_FAILURE);
	}

	pcap_t *pd;
	pcap_dumper_t *pdumper;
	pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (pd == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", output_file, errbuf);
		exit(EXIT_FAILURE);
	}

	pdumper = pcap_dump_open(pd, output_file);
	if (pdumper == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", output_file, errbuf);
		exit(EXIT_FAILURE);
	}

	fptr = fopen(offset_file, "r");
	if (fptr == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", offset_file, errbuf);
		exit(EXIT_FAILURE);
	}


	read = getline(&line, &len, fptr);
	parse_line(line, read, &begin, &end, &offset);
	init_array(array_ptr, CAPACITY, begin, offset);

	while ((read = getline(&line, &len, fptr)) != -1) {
		begin_b = begin;
		end_b = end;
		offset_b = offset;
		parse_line(line, read, &begin, &end, &offset);
		if (strncmp(strategy, "m", 1) == 0) {
			add_to_lookup_middle(array_ptr, begin_b, begin, end_b, end, offset_b, offset, nbr_pivot);
		} else if (strncmp(strategy, "s", 1) == 0) {
			add_to_lookup_step(array_ptr, begin_b, begin, end_b, end, offset_b, offset);
		} else if (strncmp(strategy, "p", 1) == 0) {
			add_array(array_ptr, begin, offset);	
		}
	}

	add_array(array_ptr, end, offset);

	//display_array(array_ptr);

	while ((packet = pcap_next(handle,&header))) {

		if (strncmp(strategy, "m", 1) == 0) {
			middle_strategy(array_ptr, packet_counter, &last_computed, &index, pdumper, packet, &header);
		} else if (strncmp(strategy, "s", 1) == 0) {
			step_strategy(array_ptr, packet_counter, &index, pdumper, packet, &header);
		} else if (strncmp(strategy, "p", 1) == 0) {
			piecewise_strategy(array_ptr, packet_counter, &index, pdumper, packet, &header);	
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
