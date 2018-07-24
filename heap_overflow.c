/* 
House of force vulnerable program.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main( int argc, char * argv[] )
{
    
    char log[200];
    char name[200];
    char p0_a[200];
    char size[200];
    char *p0,*p1,*p2;
    
    printf("Enter the name:\n");

    gets(name);

    printf("Enter the log:\n");

    gets(log);

    printf("Enter the string:\n");

	p0 = (char*)malloc(256);
	gets(p0);

	strcpy(p0_a,(char*)&p0);

	printf("Hello %s\n",name);	

	printf("Enter the size of p1 heap:\n");
	gets(size);
	p1 = (char*)malloc(strtoul(size,NULL,16));
	printf("Enter the string:\n");
	gets(p1);

	printf("Enter the size of p2 heap:\n");
	gets(size);
	p2 = (char*)malloc(strtoul(size,NULL,16));
	printf("Enter the string:\n");
	gets(p2);

	free( p0 );
	free( p1 );
	free( p2 );
	
	 return 0;
}

void helper() {
    asm("pop %rdi; pop %rsi; pop %rdx; ret"); 
}