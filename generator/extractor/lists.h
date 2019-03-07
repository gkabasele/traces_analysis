#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct node {
	void* data;
	struct node* next;
} Node;

typedef struct list {
	Node* head;
    Node* tail;
	uint64_t length;
} List;

void export_unsigned_int(void* data, FILE* fptr);
void export_float(void* data, FILE* fptr);
void export_unsigned_int_binary(void* data, FILE* fptr);
void export_float_binary(void* data, FILE* fptr);
List* emptylist();
void add(void* data, List *list, size_t data_size);
void delete(void* data, List *list);
void export_list_to_file(List *list, FILE* fptr, void(*exfunc)(void*, FILE*));
void export_list_to_file_binary(List *list, FILE* fptr, void(*exfunc)(void*, FILE*));
void destroy(List *list);
