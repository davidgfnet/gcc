/* { dg-options "-mips32" } */
NOMIPS16 unsigned int
foo32 (unsigned int x)
{
  return __builtin_bitreverse32 (x);
}
NOMIPS16 unsigned short
foo16 (unsigned short x)
{
  return __builtin_bitreverse16 (x);
}
NOMIPS16 unsigned char
foo8 (unsigned char x)
{
  return __builtin_bitreverse8 (x);
}
/* { dg-final { scan-assembler-not "\twsbh\t" } } */
/* { dg-final { scan-assembler-not "\tror\t" } } */
/* { dg-final { scan-assembler-not "\tbitrev\t" } } */
/* { dg-final { scan-assembler-not "\tbitswap\t" } } */
