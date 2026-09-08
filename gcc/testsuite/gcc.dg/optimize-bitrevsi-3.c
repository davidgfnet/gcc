/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Performs bit reverse, a 1-bit rotation, and also clears some bits.  */

#include <stdint.h>

uint32_t
bitr1(uint32_t x) {
  x = (x & 0x55555555) <<  1 | (x & 0xA2AAAAAA) >>  1;  /* -bit27 -> out 3  */
  x = (x & 0x33333333) <<  2 | (x & 0xCC4CCCCC) >>  2;  /* -bit23 -> out 8  */
  x = (x & 0x0F0F0B0F) <<  4 | (x & 0xF0F0F0F0) >>  4;  /* -bit10 -> out 21 */
  x = (x & 0x00FF00FB) <<  8 | (x & 0xFF00FF00) >>  8;  /* -bit2  -> out 25 */
  x = x << 15 | x >> 17;
  /* Bits 3, 8, 21 and 25 are clear.  */
  return x;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse32 \\\(" 1 "optimized" } } */
