#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct node {
	uint64_t data;
	struct node* next;
} Node;

typedef struct list {
	Node* head;
	uint16_t length;
} List;

List* emptylist();
void add(uint64_t data, List *list);
void delete(uint64_t data, List *list);
void export_list_to_file(List *list, FILE* fptr);
void destroy(List *list);
