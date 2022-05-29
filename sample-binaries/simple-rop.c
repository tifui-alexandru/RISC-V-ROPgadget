#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    
    FILE* fd = fopen(argv[1], "rb");

    size_t total_bytes = atoi(argv[2]);

    char buffer[8];
    fread(buffer, 1, total_bytes, fd);
    
    printf("Fail!\n");
    
    return 0;
}
