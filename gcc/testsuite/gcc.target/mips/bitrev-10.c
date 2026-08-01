/* { dg-options "isa_rev>=6 -mgp64" } */
NOMIPS16 unsigned long long
foo (unsigned long long x)
{
  return __builtin_bitreverse64 (x);
}
/* { dg-final { scan-assembler-times "\tdbitswap\t" 1 } } */
/* { dg-final { scan-assembler-times "\tdsbh\t" 1 } } */
/* { dg-final { scan-assembler-times "\tdshd\t" 1 } } */
