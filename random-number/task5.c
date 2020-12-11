#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define KEYSIZE 16
#define LEN 32 // 256 bits
void main()
{
  int i;
  unsigned char *key = (unsigned char *) malloc(sizeof(unsigned char)*LEN);
  FILE* random = fopen("/dev/urandom", "r");
  fread(key, sizeof(unsigned char)*LEN, 1, random);
  fclose(random);
  for(i=0; i<LEN; i++){
    printf("%.2x", key[i]);
  }
  printf("\n");
}
