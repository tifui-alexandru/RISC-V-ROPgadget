#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    
    FILE* fd = fopen(argv[1], "rb");

    fseek (fd , 0 , SEEK_END);
    size_t total_bytes = ftell(fd);
    rewind(fd);

    char buffer[8];
    fread(buffer, 1, total_bytes, fd);
    
    printf("Fail!\n");

    printf(buffer);

    return 0;
}
