/* { dg-options "isa_rev>=6" } */
NOMIPS16 unsigned short
foo (unsigned short x)
{
  return __builtin_bitreverse16 (x);
}
/* { dg-final { scan-assembler-times "\tbitswap\t" 1 } } */
/* { dg-final { scan-assembler-times "\twsbh\t" 1 } } */
/* { dg-final { scan-assembler-not "\tror\t" } } */
/* { dg-final { scan-assembler-not "\tbitrev\t" } } */
