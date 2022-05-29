#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    
    FILE* fd = fopen(argv[1], "rb");

    char buffer[8];

    while (!feof(fd)) {
        fread(buffer, 1, 1, 1);
    }
    
    printf("Fail!\n");
    
    return 0;
}
