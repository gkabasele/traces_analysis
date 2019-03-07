#include "lists.h"


Node *create_node(void* data, size_t data_size);

Node *create_node(void* data, size_t data_size){
	Node* newnode = malloc(sizeof(Node));
	if(newnode == NULL){
		fprintf(stderr, "Could not allocate memory for node");
		exit(EXIT_FAILURE);
	}
	newnode->data = malloc(data_size);
    if(newnode->data == NULL){
        fprintf(stderr, "Could not allocate memorey for data in node"); 
        exit(EXIT_FAILURE);
    } 
    memcpy(newnode->data, data, data_size);
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
    list->tail = NULL;
	list->length = 0;
	return list;
}


void export_unsigned_int(void* data, FILE* fptr){
    fprintf(fptr, "%u,", *(uint16_t*) data);
}

void export_float(void* data, FILE* fptr){
    fprintf(fptr, "%f,", *(float*) data);
}

void export_unsigned_int_binary(void* data, FILE* fptr){
    fwrite((uint16_t*)data, 1, sizeof(uint16_t), fptr);
}

void export_float_binary(void* data, FILE* fptr){
    fwrite((float*)data, 1, sizeof(float), fptr);
}
 
void export_list_to_file_binary(List *list, FILE* fptr, void(*exfunc)(void*, FILE*)){
    Node* current = list->head;
    if(list->head  == NULL){
        return; 
    }
    fwrite(&(list->length), 1, sizeof(list->length), fptr);
    while(current->next != NULL){
        (*exfunc)(current->data, fptr);
        current = current->next;
        //fwrite(&(current->data), 1, sizeof(current->data), fptr);  
    }
    (*exfunc)(current->data, fptr);
    
}

void export_list_to_file(List *list, FILE* fptr, void(*exfunc)(void*, FILE*)){
	Node* current = list->head;
	if(list->head == NULL){
		return;	
	}
    fprintf(fptr, "%lu\t", list->length);
	while(current->next != NULL){
        (*exfunc)(current->data, fptr);
        //fprintf(fptr, "%u,", current->data);		
		current = current->next;
	}
	//fprintf(fptr, "%u\n", current->data);
    (*exfunc)(current->data, fptr);

}

void add(void* data, List* list, size_t data_size){
	if(list->head == NULL) {
		list->head = create_node(data, data_size);	
        list->tail = list->head;
	} else {
        Node *new_data = create_node(data, data_size);
        (list->tail)->next = new_data;
        list->tail = new_data;
	}
	list->length++;
}

void delete(void* data, List* list){
	Node* current = list->head;
	Node* previous = current;
	while(current != NULL) {
		if(current->data == data) {
			previous->next = current->next;
			if(current == list->head){
				list->head = current->next;	
			}	
            free(current->data);
			free(current);
			return;
		}	
		previous = current;
		current = current->next;
	}
	list->length--;
}

void destroy(List* list){
	Node* current = list->head;
	Node* next = current;
	while(current != NULL){
		next = current->next;
        free(current->data); 
		free(current);
		current = next;	
	}
	free(list);
}
