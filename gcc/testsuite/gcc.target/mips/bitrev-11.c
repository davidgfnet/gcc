/* { dg-options "isa_rev=1 -mgp64" } */
NOMIPS16 unsigned long long
foo (unsigned long long x)
{
  return __builtin_bitreverse64 (x);
}
/* { dg-final { scan-assembler-not "\tdbitswap\t" } } */
/* { dg-final { scan-assembler-not "\tbitswap\t" } } */
/* { dg-final { scan-assembler-not "\tdshd\t" } } */
/* { dg-final { scan-assembler-not "\tdsbh\t" } } */
