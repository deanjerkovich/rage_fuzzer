/* basic mutation stuff */

#include <stdlib.h>
#include <stdio.h>
#include "rage.h"

#define FUZZ_RATIO_PC 0.05
#define CHUNK_DUPE_MAX_PC 0.25

unsigned char* do_byte_percent_mutate(unsigned char *databuf, unsigned int data_buffer_len)
{
	unsigned int bytes_to_fuzz, i, location;
	unsigned char mutatedbyte;
	bytes_to_fuzz = (data_buffer_len * FUZZ_RATIO_PC);
	for (i=0; i<bytes_to_fuzz; i++)
	{
		location = rand() % data_buffer_len;
		mutatedbyte = rand() % 256;
		databuf[location] = mutatedbyte;
	}
	return databuf;
}

//TODO: incomplete
unsigned char* do_chunk_duplicate(unsigned char *databuf, unsigned int data_buffer_len)
{
  int chunk_len;
  int dupe_num;
  int bufsz;
  int location;
  unsigned char *retbuf;
  dupe_num = rand() % 20;
  chunk_len = (rand() % data_buffer_len) * CHUNK_DUPE_MAX_PC;
  if (debug) {printf("packet len:%d, chosen chunk len:%d, dupe size:%d\n",data_buffer_len,chunk_len,dupe_num);}
  bufsz = data_buffer_len + (dupe_num*chunk_len);
  retbuf = malloc(bufsz);
  location = rand() % data_buffer_len;
  if (location+chunk_len > data_buffer_len)
  {
    location = data_buffer_len - chunk_len;
  }
  retbuf=NULL;
  return retbuf;
}

unsigned char* do_fuzz_random(unsigned char *databuf, unsigned int data_buffer_len)
{
  unsigned char *retbuf;
  retbuf = do_byte_percent_mutate(databuf, data_buffer_len);
  return retbuf;
}
