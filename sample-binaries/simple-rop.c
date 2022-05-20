#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    printf("Try to hack me!\n");
    size_t total_bytes = atoi(argv[1]);
    char buffer[8];
    memcpy(buffer, argv[2], total_bytes);
    printf("Fail!\n");
    return 0;
}