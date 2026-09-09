/* { dg-do compile } */
/* { dg-require-effective-target bitreverse } */
/* { dg-require-effective-target stdint_types } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

/* Test memory path with masking, ie. reversing all bits in 3 bytes.  */

#include <stdint.h>

static inline uint32_t
rev8(uint8_t x) {
  x = (x & 0x55) << 1 | (x & 0xAA) >> 1;
  x = (x & 0x33) << 2 | (x & 0xCC) >> 2;
  x = (x & 0x0F) << 4 | (x & 0xF0) >> 4;
  return x;
}

uint32_t
bitrev_memmask (const uint8_t *s)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return rev8(s[3]) | (rev8(s[1]) << 16) | (rev8(s[0]) << 24);
#else
  return rev8(s[0]) | (rev8(s[2]) << 16) | (rev8(s[3]) << 24);
#endif
}

/* { dg-final { scan-tree-dump-times "= __builtin_bitreverse32 \\\(" 1 "optimized" } } */
