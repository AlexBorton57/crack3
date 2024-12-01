#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileutil.h"

// DIRECTIONS
// Choose whether you are doing the 2D array or
// the array of arrays.
// For the 2D array,
//    implement loadFile2D, substringSearch2D, and free2D.
// For the array of arrays, 
//    implement loadFileAA, substringSearchAA, and freeAA.


// Load the text file from the given filename.
// Return a pointer to the array of strings.
// Sets the value of size to be the number of valid
// entries in the array (not the total array length).
char (*loadFile2D(char *filename, int *size))[COLS]
{
	FILE *in = fopen(filename, "r");
	if (!in)
	{
	    perror("Can't open file");
	    exit(1);
	}
	
	// TODO
	// Allocate memory for an 2D array, using COLS as the width.
	// initial capacity is set to 20
	int capacity = 20;
	// initial size is 0
	*size = 0;
	// buffer string
	char buffer[1000] = "";
	// initial array allocation of capacity * COLS
	char (*arr)[COLS] = malloc(capacity * sizeof(char[COLS]));
	
	// read file line by line into buffer
	while (fgets(buffer, sizeof(buffer), in) != NULL){

		// if array capacity has been reached, increase capacity by 5
		if (*size == capacity){
			capacity+=5;
			arr = realloc(arr, capacity * sizeof(char[COLS]));
		}

		// trim newline from buffer
		char *ref = strchr(buffer, '\n');
        if (ref){
            *ref = '\0';
        }

		// copy buffer string into array 
		strcpy(arr[*size], buffer);
		// increment size by 1
		(*size)++;
	}

	// close file
	fclose(in);
	// return array pointer
	return arr;
}

// Search the array for the target string.
// Return the found string or NULL if not found.
char * substringSearch2D(char *target, char (*lines)[COLS], int size)
{	
	// iterate through array
    for (int i = 0; i < size; i++){
		// checks line for substring, if it finds it, return line
		if (strstr(lines[i], target)){
			return lines[i];
		}
	}

	// return NULL if no line
    return NULL;
}

char * stringSearch2D(char *target, char (*lines)[COLS], int size)
{	
	// iterate through array
    for (int i = 0; i < size; i++){
		// checks line for string, if it finds it, return line
		if (strcmp(lines[i], target) == 0){
			return lines[i];
		}
	}

	// return NULL if no line
    return NULL;
}

// Free the memory used by the array
void free2D(char (*arr)[COLS])
{	
	// free memory from arr
	free(arr);
}