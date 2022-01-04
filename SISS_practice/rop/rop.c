#include<stdio.h>
#include<unistd.h>

void init(){
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

void gift(){
    system("What can you do with this?");
}
int main(void){
    char buf[0x20];

    init();

    read(0, buf, 0x50);

    return 0;
}


