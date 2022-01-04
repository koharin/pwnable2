//gcc -o master2 master2.c -pthread
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
void giveshell()
{
    execve("/bin/sh", NULL, NULL);
}
int thread_routine(){
    char buf[256];
    int size=0;

    printf("Size: ");
    scanf("%d", &size);

    printf("Data: ");
    read(0, buf, size);

    return 0;
}
int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    pthread_t thread_t;

    if(pthread_create(&thread_t, NULL, thread_routine, NULL) < 0){
        perror("thread create error:");
        exit(0);
    }

    pthread_join(thread_t, 0);

    return 0;
}
