#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
 
void vuln(){
        char buf[50] = "";
            void (*printf_addr)() = dlsym(RTLD_NEXT, "printf");
                printf("Printf() address : %p\n",printf_addr);
                    read(0, buf, 100);
}
 
void main(){
        vuln();
}
