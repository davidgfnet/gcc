/* { dg-options "-march=allegrex" } */
NOMIPS16 unsigned short
foo (unsigned short x)
{
  return __builtin_bitreverse16 (x);
}
/* { dg-final { scan-assembler-times "\tbitrev\t" 1 } } */
/* { dg-final { scan-assembler-times "\tsrl\t" 1 } } */
/* { dg-final { scan-assembler-not "\twsbh\t" } } */
/* { dg-final { scan-assembler-not "\tbitswap\t" } } */
