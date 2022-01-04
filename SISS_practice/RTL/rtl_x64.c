#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<dlfcn.h>
int read_input(){
    char buf[4] = "";

    read(0, buf, 0x8);

    return atoi(buf);
}

void menu(){
    printf("1. vuln\n");
    printf("2. print\n");
    printf("3. quit\n");
    printf("> ");
}
void useful_function(){
    void(*printf_addr)() = dlsym(RTLD_NEXT, "printf");
    printf("printf() addr: %p\n", printf_addr);
}
void Init(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}
int main(void){
    int choice = 0;
    char buf[0x30] = {};
    Init();
    while(1){
        menu();
        choice = read_input();
        if(choice == 1){
            printf("input: ");
            read(0, buf, 0x60);
        }
        else if(choice == 2)
            useful_function();
        else{
            if(choice == 3) break;
            else  printf("Invalid choice\n");
        }
    }
    return 0;
}


