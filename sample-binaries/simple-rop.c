#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    
    FILE* fd = fopen(argv[1], "rb");
    char buffer[8];

    char c;
    for (int i = 0; (c = getc(fd)) != EOF; i++) {
        buffer[i] = c;
    }
    
    printf("Fail!\n");
    
    return 0;
}
