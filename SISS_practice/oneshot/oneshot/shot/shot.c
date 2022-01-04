#include<stdio.h>
#include<signal.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
void menu(){
    printf("1. read\n");
    printf("2. print\n");
    printf("3. quit\n");
    printf("> ");
}
int Input(){
    char buf[4]="";

    read(0, buf, 8);
    return atoi(buf);
}
void handler(){
    printf("Time Out\n");
    exit(-1);
}
void Init(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, handler);
    alarm(60);
}
int main(int argc, char *argv[]){
    char buf[0x10];
    bool choice=true;
    size_t num = 0;
    
    Init();
    while(choice){
        menu();
        switch(Input()){
            case 1:
                read(0, buf, 56);
                break;
            case 2:
                printf("stdin: %p\n", stdin);
                break;
            case 3:
                choice=false;
                break;
            default:
                printf("Invalid choice\n");
                break;
        }
    }

    if(num > 0) exit(0);

    printf("message: %s\n", buf);   
    memset(buf, 0, sizeof(buf));
    
    return 0;
}

        

        

    
    

