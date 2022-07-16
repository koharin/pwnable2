#include <stdio.h>
#include <string.h>

char *flag = "EKO{THIS_IS_FLAG_FOR_LOCAL}";
void get_flag(char *str){
    strcpy(str, flag);
}
