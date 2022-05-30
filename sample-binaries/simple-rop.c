#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    
    FILE* fd = fopen(argv[1], "rb");

    fseek(fd , 0 , SEEK_END);
    size_t total_bytes = ftell(fd);
    rewind(fd);

    size_t max_code_size = 10000;
    char buffer[max_code_size];
    fread(buffer, 1, total_bytes, fd);
    
    printf("Fail!\n");
    
    return 0;
}