#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main(void)
{
    char buf[0x100];
    setvbuf(stdout, 0, 2, 0);

    read(0, buf, 0x100);
    printf(buf);
    read(0, buf, 0x100);
    printf(buf);

}
