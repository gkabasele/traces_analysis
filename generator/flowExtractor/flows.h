#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include "uthash.h"
#include "lists.h"

#define ANY "any"
#define ANYPORT 0

typedef int bool;
#define true 1
#define false 0

typedef struct {
	uint64_t high;
	uint64_t low;
} uint128_t;

typedef struct {
     uint32_t   srcIp;
     uint32_t   destIp;
     uint16_t  	srcPort;
     uint16_t  	destPort;
     uint8_t 	ipProto;
} flowv4_key;

typedef struct {
     flowv4_key key;
	 //Statistics for the flow
	 uint64_t 		total_size;
	 uint64_t		nbr_pkts;
     struct timeval first_seen;
	 struct timeval last_seen;
     List*          pkt_dist;
     List*          arr_dist;
     UT_hash_handle hh;
} flowv4_record;

typedef struct {
	uint64_t bytes_out;
	uint64_t bytes_in;
	uint64_t pkt_out;
	uint64_t pkt_in;
	uint64_t udp_nbr;
	uint64_t tcp_nbr;
	uint64_t bna_nbr;
	uint64_t hmi_nbr;

} hourly_stats;

typedef struct {
	uint128_t 	srcIp;
	uint128_t 	destIp;
	uint16_t 	srcPort;
    uint16_t  	destPort;
    uint8_t 	ipProto;
} flowv6_key;

typedef struct {
	flowv6_key key;
	//Statistics for the flow
	unsigned int	tgh;
	uint16_t		avg_size;
	uint16_t		max_size;
	uint64_t 		total_size;
	uint64_t		nbr_pkts;
	struct timeval 	first_seen;
	struct timeval 	last_seen;
	UT_hash_handle hh;
} flowv6_record;


flowv4_record* create_flowv4_record(uint32_t srcIp, uint32_t destIp, uint16_t srcPort, 
				uint16_t destPort, uint8_t ipProto, struct timeval ts);
flowv6_record* create_flowv6_record(uint128_t srcIp, uint128_t destIp, uint16_t srcPort, 
									uint16_t destPort, uint8_t ipProto);

void add_flowv4(flowv4_record** hash, flowv4_record *record);
void add_flowv6(flowv6_record** hash, flowv6_record *record);
flowv4_record* existing_flowv4(flowv4_record** hash,flowv4_record *record);
flowv6_record* existing_flowv6(flowv6_record** hash,flowv6_record *record);
void clear_hash_recordv4(flowv4_record**  hash_table);
void clear_hash_recordv6(flowv6_record**  hash_table);
void display_flowv4(flowv4_record* flow, FILE* fptr, bool normal);
void display_flowv6(flowv6_record* flow);
void update_stats(flowv4_record* record, uint16_t size, struct timeval ts);
uint32_t compute_inter_arrival(struct timeval* t1, struct timeval* t2);
void export_flowv4_to_file(flowv4_record* flow, FILE* fptr);
void export_binary_flowv4_to_file(flowv4_record* flow, FILE* fptr);
void export_allv4_to_file(flowv4_record** hash_table, FILE* fptr);
void export_binary_allv4_to_file(flowv4_record** hash_table, FILE* fptr);
bool compare_outgoing(flowv4_record* f1, flowv4_record* f2);
bool compare_incoming(flowv4_record* f1, flowv4_record* f2);
hourly_stats* init_hourly_stats();
void reset_hourly_stats(hourly_stats* stats);
void destroy_hourly_stats(hourly_stats* stats);
