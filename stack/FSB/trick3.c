// gcc -o trick3 trick3.c -z now
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void menu(void)
{
    puts("1. malloc");
    puts("2. free");
    puts("3. fsb");
    puts("4. exit");
    printf("> ");
}

int main(void)
{
    int n;
    char *heap;
    char buf[0x100];

    setvbuf(stdout, 0, 2, 0);

    while(1)
    {
        menu();
        scanf("%d", &n);
        switch(n)
        {
            case 1:
                heap = malloc(0x20);
                printf("> ");
                read(0, heap, 0x20);
                break;
            case 2:
                free(heap);
                break;
            case 3:
                printf("> ");
                read(0, buf, 0x100);
                printf(buf);
                break;
            default:
                exit(0);
         }
    }
}
