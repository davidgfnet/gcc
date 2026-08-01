/* { dg-options "isa_rev>=6" } */
NOMIPS16 unsigned char
foo (unsigned char x)
{
  return __builtin_bitreverse8 (x);
}
/* { dg-final { scan-assembler-times "\tbitswap\t" 1 } } */
/* { dg-final { scan-assembler-not "\twsbh\t" } } */
/* { dg-final { scan-assembler-not "\tror\t" } } */
/* { dg-final { scan-assembler-not "\tbitrev\t" } } */
