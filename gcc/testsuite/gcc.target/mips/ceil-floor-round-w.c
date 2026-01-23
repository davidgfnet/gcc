/* { dg-options "isa>=2 -mhard-float -ffast-math" } */

NOMIPS16 long
ceilf_to_long (float x)
{
  return __builtin_lceilf(x);
}

NOMIPS16 long
floorf_to_long (float x)
{
  return __builtin_lfloorf(x);
}

NOMIPS16 long
roundf_to_long (float x)
{
  return __builtin_lroundf(x);
}

NOMIPS16 long
ceild_to_long (double x)
{
  return __builtin_lceil(x);
}

NOMIPS16 long
floord_to_long (double x)
{
  return __builtin_lfloor(x);
}

NOMIPS16 long
roundd_to_long (double x)
{
  return __builtin_lround(x);
}

/* { dg-final { scan-assembler "\tceil\\.w\\.s\t" } } */
/* { dg-final { scan-assembler "\tfloor\\.w\\.s\t" } } */
/* { dg-final { scan-assembler "\tround\\.w\\.s\t" } } */
/* { dg-final { scan-assembler "\tceil\\.w\\.d\t" } } */
/* { dg-final { scan-assembler "\tfloor\\.w\\.d\t" } } */
/* { dg-final { scan-assembler "\tround\\.w\\.d\t" } } */
