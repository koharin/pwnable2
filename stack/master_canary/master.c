//gcc -o master master.c
#include<stdio.h>
#include<unistd.h>

int main()
{
    char buf[256];

    read(0, buf, 256);

}
