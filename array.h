#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <stdint.h>

typedef struct { 
	uint16_t x; 
   	float y;
} coord_t;

typedef struct {
	coord_t *array;
	int size;
	int capacity;
} interp_array_t;

void init_array(interp_array_t *a, int capacity, uint16_t x, float y);

void add_array(interp_array_t *a, uint16_t x, float y);

void destroy_array(interp_array_t *a);

void display_array(interp_array_t *a);


