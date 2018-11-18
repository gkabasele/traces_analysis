#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct node {
	uint32_t data;
	struct node* next;
} Node;

typedef struct list {
	Node* head;
	uint64_t length;
} List;

List* emptylist();
void add(uint32_t data, List *list);
void delete(uint32_t data, List *list);
void export_list_to_file(List *list, FILE* fptr);
void export_list_to_file_binary(List *list, FILE* fptr);
void destroy(List *list);
