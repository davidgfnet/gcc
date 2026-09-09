/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test a common implementation of bitreverse, from Hacker's Delight.  */

#include <stdint.h>

uint16_t
bitrhi(uint16_t x) {
  x = (x & 0x5555) <<  1 | (x & 0xAAAA) >>  1;
  x = (x & 0x3333) <<  2 | (x & 0xCCCC) >>  2;
  x = (x & 0x0F0F) <<  4 | (x & 0xF0F0) >>  4;
  x = (x & 0x00FF) <<  8 | (x & 0xFF00) >>  8;
  return x;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse16 \\\(" 1 "optimized" } } */
