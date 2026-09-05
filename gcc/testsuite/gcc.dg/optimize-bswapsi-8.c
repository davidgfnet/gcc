/* { dg-do compile } */
/* { dg-require-effective-target bswap } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test bswap + arbitrary rotation (not just multiple of 8).  */

#include <stdint.h>

uint32_t
swap_and_rotate (uint32_t a)
{
  return (a & 0x000000FF) << 23 |
         (a & 0x0000FF00) << 7  |
         (a & 0x00FF0000) >> 9  |
         (a & 0xFE000000) >> 25 |
         (a & 0x01000000) << 7;
}

/* { dg-final { scan-tree-dump-times "= __builtin_bswap32 \\\(" 1 "optimized" } } */
/* { dg-final { scan-tree-dump-times " r>> 1;" 1 "optimized" } } */
