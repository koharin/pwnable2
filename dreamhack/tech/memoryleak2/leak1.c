//gcc -o leak1 leak1.c
#include<stdio.h>
#include<stdlib.h>

int main(){
    char *ptr = malloc(0x420);
    char *ptr2 = malloc(0x420);

    free(ptr);

    ptr = malloc(0x420);
    //ptr = malloc(0x200);

    printf("0x%lx\n", *(long long*)ptr);

    return 0;
}
