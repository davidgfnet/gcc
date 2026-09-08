/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test a common implementation of bitreverse, from Hacker's Delight.  */

#include <stdint.h>

uint64_t
bitrdi(uint64_t x) {
  x = (x & 0x5555555555555555ULL) <<  1 | (x & 0xAAAAAAAAAAAAAAAAULL) >>  1;
  x = (x & 0x3333333333333333ULL) <<  2 | (x & 0xCCCCCCCCCCCCCCCCULL) >>  2;
  x = (x & 0x0F0F0F0F0F0F0F0FULL) <<  4 | (x & 0xF0F0F0F0F0F0F0F0ULL) >>  4;
  x = (x & 0x00FF00FF00FF00FFULL) <<  8 | (x & 0xFF00FF00FF00FF00ULL) >>  8;
  x = (x & 0x0000FFFF0000FFFFULL) << 16 | (x & 0xFFFF0000FFFF0000ULL) >> 16;
  x = (x & 0x00000000FFFFFFFFULL) << 32 | (x & 0xFFFFFFFF00000000ULL) >> 32;
  return x;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse64 \\\(" 1 "optimized" } } */
