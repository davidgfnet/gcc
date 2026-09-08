/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* A variant similar to the "canonical" bit exchange scheme, with bswap.  */

#include <stdint.h>

uint32_t
rev_variant1(uint32_t n) {
  n = ((n & 0x55555555) <<  1) | ((n >>  1) & 0x55555555);
  n = ((n & 0x33333333) <<  2) | ((n >>  2) & 0x33333333);
  n = ((n & 0x0F0F0F0F) <<  4) | ((n >>  4) & 0x0F0F0F0F);
  n = (n << 24) | ((n & 0xFF00) << 8) | ((n >> 8) & 0xFF00) | (n >> 24);
  return n;
}

/* A couple of variants from Hacker's Delight.  */

inline uint32_t
rot32(uint32_t x, uint32_t amount) {
   return (x << amount) | (x >> (32 - amount));
}

uint32_t
rev12(uint32_t n) {
  n = rot32(n & 0x00FF00FF, 16) | (n & ~0x00FF00FF);
  n = rot32(n & 0x0F0F0F0F,  8) | (n & ~0x0F0F0F0F);
  n = rot32(n & 0x33333333,  4) | (n & ~0x33333333);
  n = rot32(n & 0x55555555,  2) | (n & ~0x55555555);
  return rot32(n, 1);
}

/* Reverses 27 bits only.  Emitted with rotation + masking.  */
uint32_t
rev13(uint32_t n) {
  n = (n & 0x000001FF) << 18 | (n & 0x0003FE00) | (n >> 18) & 0x000001FF;
  n = (n & 0x001C0E07) <<  6 | (n & 0x00E07038) | (n >>  6) & 0x001C0E07;
  n = (n & 0x01249249) <<  2 | (n & 0x02492492) | (n >>  2) & 0x01249249;
  return n;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse32 \\\(" 3 "optimized" } } */
