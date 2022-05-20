#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    char buffer[15];
    printf("Try to spawn a shell!\n");
    strcpy(buffer, argv[1]);
    printf("Fail!\n");
    return 0;
} 