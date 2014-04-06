
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "tree.h"
#include "tm_p.h"
#include "flags.h"
#include "c-family/c-common.h"
#include "ggc.h"
#include "target.h"
#include "target-def.h"
#include "cpplib.h"
#include "c-family/c-pragma.h"

void o386_target_macros (struct cpp_reader *pfile) {
  /* 32/64-bit won't change with target specific options, so do the assert and
 *      builtin_define_std calls here.  */
  
  cpp_assert (parse_in, "cpu=i386");
  cpp_assert (parse_in, "machine=i386");
  cpp_define (pfile, "__i386__");
}


