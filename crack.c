#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

#if __has_include("fileutil.h")
#include "fileutil.h"
#endif

#define PASS_LEN 50     // Maximum length any password will be.
#define HASH_LEN 33     // Length of hash plus one for null.


int main(int argc, char *argv[])
{
    // ensures that proper command line arguments are used
    if (argc < 3) 
    {
        printf("Usage: %s hash_file dictionary_file\n", argv[0]);
        exit(1);
    }

    // variables
    int size;
    int hashCount = 0;

    // 2d array containing list of hashes
    char (*hashes)[HASH_LEN] = loadFile2D(argv[1], &size);
    
    // stores hash of plaintext
    char *hash;
    // buffer
    char buffer[PASS_LEN];
    // opens file containing plaintext to be hashed and compared to hash list
    FILE *dictionary = fopen(argv[2], "r");
    // ensures file opens properly
    if (!dictionary)
	{
	    perror("Can't open file");
	    exit(1);
	}

    // while plaintext is recieved
    while (fgets(buffer, sizeof(buffer), dictionary) != NULL){
        // trim newline from buffer
        char *ref = strchr(buffer, '\n');
        if (ref){
            *ref = '\0';
        }
        // hashes plaintext
        hash = md5(buffer, strlen(buffer));
        // determines if hashed plaintext matches existing hash
        char *found = stringSearch2D(hash, hashes, size);
        if (found){
            // print hash and plaintext, free hash, increment hashCount
            printf("%s %s\n", hash, buffer);
            free(hash);
            hashCount++;
        }
    }

    // close file and free hashes
    fclose(dictionary);
    free(hashes);
    // print final matched hash count
    printf("Hash count: %d\n", hashCount);
    
}
