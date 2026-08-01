/* { dg-options "isa_rev>=6" } */
NOMIPS16 unsigned int
foo (unsigned int x)
{
  return __builtin_bitreverse32 (x);
}
/* { dg-final { scan-assembler "\tbitswap\t" } } */
/* { dg-final { scan-assembler "\twsbh\t" } } */
/* { dg-final { scan-assembler "\tror\t" } } */
/* { dg-final { scan-assembler-not "\tbitrev\t" } } */
