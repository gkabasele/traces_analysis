#include <stdio.h>
#include <stdlib.h>

typedef struct { 
	int x;
   	float y;
} coord_t;

typedef struct {
	coord_t *array;
	int size;
	int capacity;
} interp_array_t;

void init_array(interp_array_t *a, int capacity, int x, float y);

void add_array(interp_array_t *a, int x, float y);

void destroy_array(interp_array_t *a);

void display_array(interp_array_t *a);


