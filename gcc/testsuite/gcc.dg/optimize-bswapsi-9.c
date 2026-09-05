/* { dg-do compile } */
/* { dg-require-effective-target bswap } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test bswap + masking, where the mask is (almost) arbitrary.  */

#include <stdint.h>

uint32_t
partial_swap (uint32_t a)
{
  a = (a & 0x000000C3) << 24 |
      (a & 0x0000F000) << 8  |
      (a & 0x003F0000) >> 8  |
      (a & 0x7F000000) >> 24;
  return a;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bswap32 \\\(" 1 "optimized" } } */
