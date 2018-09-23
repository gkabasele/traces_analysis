#include "flows.h"
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8201Q (0x8100)


hourly_stats* init_hourly_stats(){
	hourly_stats* new = (hourly_stats* ) malloc(sizeof(hourly_stats));
	if (new == NULL){
		fprintf(stderr, "Could not allocate memory for hourly stats");
		exit(EXIT_FAILURE);	
	}
	reset_hourly_stats(new);
	return new;
}

void reset_hourly_stats(hourly_stats* stats){
	stats->bytes_out = 0;
	stats->bytes_in = 0;
	stats->pkt_out = 0;
	stats->pkt_in = 0;
}

void destroy_hourly_stats(hourly_stats* stats){
	free(stats);
}

void print_time(struct timeval ts, char *tmbuf, size_t lentmbuf, char *buf, size_t lenbuf){
	time_t tmp;
	struct tm *tmptm;

	tmp = ts.tv_sec;
	tmptm = localtime(&tmp);
	strftime(tmbuf, lentmbuf, "%Y-%m-%d %H:%M:%S", tmptm);
	snprintf(buf, lenbuf, "%s.%06ld", tmbuf, ts.tv_usec);
}

uint64_t timeval_to_ms(struct timeval* tv){
	uint64_t millis = (tv->tv_sec * (uint64_t) 1000) + (tv->tv_usec/1000);
	return millis;

}

void display_flowv4(flowv4_record* flow, FILE* fptr, bool normal){
	struct in_addr s_in;
	s_in.s_addr = flow->key.srcIp;
	struct in_addr d_in;
	d_in.s_addr = flow->key.destIp;
	char *tmp = inet_ntoa(s_in);
	char srcip[INET_ADDRSTRLEN];
	char destip[INET_ADDRSTRLEN];
	strncpy(srcip, tmp, INET_ADDRSTRLEN);
	tmp = inet_ntoa(d_in);
	strncpy(destip, tmp, INET_ADDRSTRLEN);
	if(normal){
		fprintf(fptr, "%s:%u<-->%s:%u %u\n",
	                   srcip,flow->key.srcPort,
	                   destip, flow->key.destPort,flow->key.ipProto);
	} else {
		fprintf(fptr, "%s:%u<-->%s:%u %u\n",
					   destip, flow->key.destPort,
			   		   srcip, flow->key.srcPort, flow->key.ipProto);		   
	}
	
}

void export_flowv4_to_file(flowv4_record* flow, FILE* fptr){
	
	struct in_addr s_in;
	s_in.s_addr = flow->key.srcIp;
	struct in_addr d_in;
	d_in.s_addr = flow->key.destIp;
	char *tmpaddr = inet_ntoa(s_in);
	char srcip[INET_ADDRSTRLEN];
	char destip[INET_ADDRSTRLEN];	
	strncpy(srcip, tmpaddr, INET_ADDRSTRLEN);
	tmpaddr = inet_ntoa(d_in);
	strncpy(destip, tmpaddr, INET_ADDRSTRLEN);

	char tmfirst[64], first[64];
   	char tmlast[64], last[64];	

	print_time(flow->first_seen, tmfirst, 64, first, 64);
	print_time(flow->last_seen, tmlast, 64, last, 64);

	uint64_t res_arrival = 0;	
	
	if (flow->nbr_pkts > 1) {
		res_arrival = flow->avg_interarrival/(flow->nbr_pkts-1);
	}
	struct timeval tmp;
	timersub(&(flow->last_seen),&(flow->first_seen), &tmp);

	uint64_t duration = timeval_to_ms(&tmp); 

	fprintf(fptr, "%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%lu\t%lu\t%lu\t%s\t%s\t%lu\t%lu\n",
			srcip, destip, flow->key.srcPort, flow->key.destPort, flow->key.ipProto,
			flow->tgh, flow->avg_size, flow->max_size, flow->total_size, flow->total_wire_size,
			flow->nbr_pkts, first, last, res_arrival, duration);

}

void export_allv4_to_file(flowv4_record** hash_table, FILE* fptr){
	flowv4_record* current, *tmp;
	HASH_ITER(hh, *hash_table, current, tmp){
		export_flowv4_to_file(current, fptr); 	
	}
}

void clear_hash_recordv4(flowv4_record** hash_table){
	flowv4_record* current,*tmp;
	HASH_ITER(hh,*hash_table,current,tmp){
	    HASH_DEL(*hash_table,current);
	    free(current);
	}
}

flowv4_record* create_flowv4_record(uint32_t srcIp, uint32_t destIp, 
						uint16_t srcPort, uint16_t destPort, 
						uint8_t ipProto, struct timeval ts){
    flowv4_record* flow;
    flow = (flowv4_record*) malloc (sizeof(flowv4_record));
    if(flow!=NULL){
        memset(flow,0,sizeof(flowv4_record));
		flow->first_seen = ts;
		flow->last_seen = ts;
		(flow->key).srcIp = srcIp;
		(flow->key).destIp = destIp;
        flow->key.srcPort = srcPort;
        flow->key.destPort = destPort;
        flow->key.ipProto = ipProto;
        return flow;
    } else {
        printf("[create_flow]-Could not allocate memory for flow");
        return NULL;
    }
}


void add_flowv4(flowv4_record** hash, flowv4_record *record){
    HASH_ADD(hh,*hash,key,sizeof(flowv4_key),record);
}

flowv4_record* existing_flowv4(flowv4_record** hash,flowv4_record *record){
    flowv4_record* flow;
    HASH_FIND(hh,*hash, &(record->key),sizeof(flowv4_key),flow);
    return flow;
}

void update_stats(flowv4_record* flow, uint16_t size, uint16_t wire_size, struct timeval ts){
	flow->total_size += size;
	flow->total_wire_size += wire_size;
	flow->nbr_pkts += 1;

	struct timeval tmp;
	timersub(&ts, &(flow->last_seen), &tmp);

	flow->avg_interarrival += timeval_to_ms(&tmp);
	flow->last_seen = ts;
	if (size > flow->max_size) {
		flow->max_size = size;	
	}
}

bool compare_outgoing(flowv4_record* f1, flowv4_record* f2){
	return (f1->key.srcIp == f2->key.srcIp &&
			f1->key.destIp == f2->key.destIp &&
			f1->key.ipProto == f2->key.ipProto &&
			f1->key.srcPort == f2->key.srcPort &&
			f1->key.destPort == f2->key.destPort);	
}

bool compare_incoming(flowv4_record* f1, flowv4_record* f2){
	return (f1->key.srcIp == f2->key.destIp &&
			f1->key.destIp == f2->key.srcIp &&
			f1->key.ipProto == f2->key.ipProto &&
			f1->key.srcPort == f2->key.destPort &&
			f1->key.destPort == f2->key.srcPort);
}

// IPv6 version
void add_flowv6(flowv6_record** hash, flowv6_record *record){
    HASH_ADD(hh,*hash,key,sizeof(flowv6_key),record);
}

flowv6_record* existing_flowv6(flowv6_record** hash,flowv6_record *record){
	flowv6_record* flow;
    HASH_FIND(hh,*hash, &(record->key),sizeof(flowv6_key),flow);
    return flow;
}

flowv6_record* create_flowv6_record(uint128_t srcIp, uint128_t destIp, uint16_t srcPort,
			   						uint16_t destPort, uint8_t ipProto){
	flowv6_record* flow;
    flow = (flowv6_record*) malloc (sizeof(flowv6_record));
    if(flow!=NULL){
        memset(flow,0,sizeof(flowv6_record));
		(flow->key).srcIp = srcIp;
		(flow->key).destIp = destIp;
        flow->key.srcPort = srcPort;
        flow->key.destPort = destPort;
        flow->key.ipProto = ipProto;
        return flow;
    } else {
        printf("[create_flow]-Could not allocate memory for flow");
        return NULL;
    }
}

void clear_hash_recordv6(flowv6_record**  hash_table){
	flowv6_record* current,*tmp;
	HASH_ITER(hh,*hash_table,current,tmp){
	    HASH_DEL(*hash_table,current);
	    free(current);
	}
}

void display_flowv6(flowv6_record* flow){

}
