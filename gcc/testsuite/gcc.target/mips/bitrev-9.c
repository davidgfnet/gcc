/* { dg-options "-march=allegrex" } */
NOMIPS16 unsigned char
foo (unsigned char x)
{
  return __builtin_bitreverse8 (x);
}
/* { dg-final { scan-assembler-times "\tbitrev\t" 1 } } */
/* { dg-final { scan-assembler-times "\tsrl\t" 1 } } */
/* { dg-final { scan-assembler-not "\twsbh\t" } } */
/* { dg-final { scan-assembler-not "\tbitswap\t" } } */
