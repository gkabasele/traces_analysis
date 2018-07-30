#include "array.h"


void init_array(interp_array_t *a, int capacity) {
	a->array = (coord_t*) malloc(capacity * sizeof(coord_t));
	if (a->array != NULL) {
		a->size = 0;
		a->capacity = capacity;
	} else {
		fprintf(stderr, "Could not allocate memory: init_array\n");
		exit(EXIT_FAILURE);
	}
}

void add_array(interp_array_t *a, int x, float y) {
	if (a->size >= a->capacity){
		a->capacity *= 2;
		a->array = (coord_t*) realloc(a->array, (a->capacity) * sizeof(coord_t));
	}

	if (a->array == NULL){
		fprintf(stderr, "Could not allocate memory: add array\n");	
		exit(EXIT_FAILURE);
	}

	a->array[a->size+1].x = x;
	a->array[a->size+1].y = y;
	a->size++;
}

void destroy_array(interp_array_t *a) {
	free(a->array);
	a->array = NULL;
	a->size = 0;
}
