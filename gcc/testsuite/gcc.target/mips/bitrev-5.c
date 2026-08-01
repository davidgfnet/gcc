/* { dg-options "-march=allegrex" } */
NOMIPS16 unsigned int
foo (unsigned int x)
{
  return __builtin_bitreverse32 (x);
}
/* { dg-final { scan-assembler-times "\tbitrev\t" 1 } } */
/* { dg-final { scan-assembler-not "\twsbh\t" } } */
/* { dg-final { scan-assembler-not "\tror\t" } } */
