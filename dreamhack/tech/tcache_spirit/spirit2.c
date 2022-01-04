//gcc -o spirit2 spirit2.c -no-pie
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void giveshell()
{
    system("/bin/sh"); 
}
int main()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    
    char *ptr[10] = {0,};

    long long idx = 0;
    size_t size = 0;
    long long index = 0;
    size_t address = 0;
    int i = 0;
    size_t *ptr_size[10] = {0,};

    printf("%p\n", &size);

    while(1){
        printf("1. Add\n");
        printf("2. Free\n");
        printf("3. Edit\n");
        printf("> ");
        scanf("%d", &idx);
        switch(idx){
            case 1:
                if(i>=10) break;
                printf("Size: ");
                scanf("%llu", &size);
		ptr[i] = malloc(size);
    		ptr_size[i] = size;
		i++;
		break;
	    case 2:
		printf("Address: ");
		scanf("%lld", &address);
		free(address);
		break;
	    case 3:
		printf("Index: ");
		scanf("%llu", &index);
		read(0, ptr[index], ptr_size[index]);
		break;
 	    default:
		return 0;
	}
    }
    return 0;
}	
