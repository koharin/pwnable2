#include<stdio.h>

char buf[0x100];
int main(){
    printf("Format String Bug: ");
    gets(buf);
    printf(buf);

    return 0;
}
