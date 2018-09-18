#include "flows.h"
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8201Q (0x8100)

void display_flowv4(flowv4_record* flow){
	printf("(Prot:%d) %s:%d<>%s:%d\n",
	                   flow->key.ipProto,flow->key.srcIp,flow->key.srcPort,
	                   flow->key.destIp,flow->key.destPort);

}

void display_flowv6(flowv6_record* flow){

}

void clear_hash_recordv4(flowv4_record** hash_table){
	flowv4_record* current,*tmp;
	HASH_ITER(hh,*hash_table,current,tmp){
	    HASH_DEL(*hash_table,current);
	    free(current);
	}
}


void clear_hash_recordv6(flowv6_record**  hash_table){
	flowv6_record* current,*tmp;
	HASH_ITER(hh,*hash_table,current,tmp){
	    HASH_DEL(*hash_table,current);
	    free(current);
	}
}


flowv4_record* create_flowv4_record(uint32_t srcIp, uint32_t destIp, uint16_t srcPort, uint16_t destPort, uint8_t ipProto){
    flowv4_record* flow;
    flow = (flowv4_record*) malloc (sizeof(flowv4_record));
    if(flow!=NULL){
        memset(flow,0,sizeof(flowv4_record));
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

void add_flowv4(flowv4_record** hash, flowv4_record *record){
    HASH_ADD(hh,*hash,key,sizeof(flowv4_key),record);
}

void add_flowv6(flowv6_record** hash, flowv6_record *record){
    HASH_ADD(hh,*hash,key,sizeof(flowv6_key),record);
}

flowv4_record* existing_flowv4(flowv4_record** hash,flowv4_record *record){
    flowv4_record* flow;
    HASH_FIND(hh,*hash, &(record->key),sizeof(flowv4_key),flow);
    return flow;
}

flowv6_record* existing_flowv6(flowv6_record** hash,flowv6_record *record){
	flowv6_record* flow;
    HASH_FIND(hh,*hash, &(record->key),sizeof(flowv6_key),flow);
    return flow;
}
