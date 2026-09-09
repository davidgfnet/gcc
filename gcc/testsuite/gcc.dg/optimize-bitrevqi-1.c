/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test a common implementation of bitreverse, from Hacker's Delight.  */

#include <stdint.h>

uint8_t
bitrqi(uint8_t x) {
  x = (x & 0x55) <<  1 | (x & 0xAA) >>  1;
  x = (x & 0x33) <<  2 | (x & 0xCC) >>  2;
  x = (x & 0x0F) <<  4 | (x & 0xF0) >>  4;
  return x;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse8 \\\(" 1 "optimized" } } */
