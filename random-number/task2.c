#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define KEYSIZE 16
void main()
{
int i;
int j;
char key[KEYSIZE];
printf("%lld\n", (long long) time(NULL));
for (j=1524013729; j<=1524020929;j++){
srand (j);
for (i = 0; i< KEYSIZE; i++){
key[i] = rand()%256;
printf("%.2x", (unsigned char)key[i]);
}
printf("\n");
}
}
