#include "lists.h"


Node *create_node(uint64_t data);

Node *create_node(uint64_t data){
	Node* newnode = malloc(sizeof(Node));
	if(newnode == NULL){
		fprintf(stderr, "Could not allocate memory for node");
		exit(EXIT_FAILURE);
	}
	newnode->data = data;
	newnode->next = NULL;
	return newnode;
}

List *emptylist(){
	List* list =  malloc(sizeof(List));
	if(list == NULL){
		fprintf(stderr, "Could not allocate memory for the list");	
		exit(EXIT_FAILURE);
	}
	list->head = NULL;
	return list;
}

void export_list_to_file(List *list, FILE* fptr){
	Node* current = list->head;
	if(list->head == NULL){
		return;	
	}
	while(current->next != NULL){
		fprintf(fptr, "%lu\t", current->data);		
		current = current->next;
	}
	fprintf(fptr, "%lu\n", current->data);

}

void add(uint64_t data, List* list){
	Node* current = NULL;
	if(list->head == NULL) {
		list->head = create_node(data);	
	} else {
		current = list->head;
		while(current->next != NULL) {
			current = current->next;	
		}
		current->next = create_node(data);
	}
}

void delete(uint64_t data, List* list){
	Node* current = list->head;
	Node* previous = current;
	while(current != NULL) {
		if(current->data == data) {
			previous->next = current->next;
			if(current == list->head){
				list->head = current->next;	
			}	
			free(current);
			return;
		}	
		previous = current;
		current = current->next;
	}
}

void destroy(List* list){
	Node* current = list->head;
	Node* next = current;
	while(current != NULL){
		next = current->next;
		free(current);
		current = next;	
	}
	free(list);
}
