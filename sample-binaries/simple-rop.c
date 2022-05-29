#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    
    char buffer[8];
    size_t total_bytes = atoi(argv[1]);
    memcpy(buffer, argv[2], total_bytes);
    
    printf("Fail!\n");
    
    return 0;
}
