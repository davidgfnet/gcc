/* { dg-do compile } */
/* { dg-options "-O2 -mno-gfni" } */

/* Check that bit reverse is still recognized and expanded using bswap.  */

unsigned int
bitr1(unsigned int x) {
  x = (x & 0x55555555) <<  1 | (x & 0xAAAAAAAA) >>  1;
  x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
  x = (x & 0x33333333) <<  2 | (x & 0xCCCCCCCC) >>  2;
  x = (x & 0x00FF00FF) <<  8 | (x & 0xFF00FF00) >>  8;
  x = (x & 0x0F0F0F0F) <<  4 | (x & 0xF0F0F0F0) >>  4;
  return x;
}

/* { dg-final { scan-assembler-times "bswap" 1 } } */
