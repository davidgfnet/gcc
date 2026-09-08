/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test a common implementation of bitreverse, from Hacker's Delight.  */

#include <stdint.h>

uint32_t
bitr1(uint32_t x) {
  x = (x & 0x55555555) <<  1 | (x & 0xAAAAAAAA) >>  1;
  x = (x & 0x33333333) <<  2 | (x & 0xCCCCCCCC) >>  2;
  x = (x & 0x0F0F0F0F) <<  4 | (x & 0xF0F0F0F0) >>  4;
  x = (x & 0x00FF00FF) <<  8 | (x & 0xFF00FF00) >>  8;
  x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
  return x;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse32 \\\(" 1 "optimized" } } */
