//gcc -o full_entry full_entry.c -no-pie
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
int main(){
    uint64_t *ptr[10];

    int i;

    for(i=0;i<9;i++){
        ptr[i] = malloc(0x100);
    }

    for(i=0;i<7;i++){ //tcache_entry
        free(ptr[i]);
    }

    free(ptr[7]); //unsorted bin

    printf("fd: %lp\n", *ptr[7]);

    return 0;
}
