/* { dg-options "isa>=3 -mabi=64 -mhard-float -ffast-math" } */

NOMIPS16 long long
ceilf_to_llong (float x)
{
  return __builtin_llceilf(x);
}

NOMIPS16 long long
floorf_to_llong (float x)
{
  return __builtin_llfloorf(x);
}

NOMIPS16 long long
roundf_to_llong (float x)
{
  return __builtin_llroundf(x);
}

NOMIPS16 long long
ceild_to_llong (double x)
{
  return __builtin_llceil(x);
}

NOMIPS16 long long
floord_to_llong (double x)
{
  return __builtin_llfloor(x);
}

NOMIPS16 long long
roundd_to_llong (double x)
{
  return __builtin_llround(x);
}

/* { dg-final { scan-assembler "\tceil\\.l\\.s\t" } } */
/* { dg-final { scan-assembler "\tfloor\\.l\\.s\t" } } */
/* { dg-final { scan-assembler "\tround\\.l\\.s\t" } } */
/* { dg-final { scan-assembler "\tceil\\.l\\.d\t" } } */
/* { dg-final { scan-assembler "\tfloor\\.l\\.d\t" } } */
/* { dg-final { scan-assembler "\tround\\.l\\.d\t" } } */
