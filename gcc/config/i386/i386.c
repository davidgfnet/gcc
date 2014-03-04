/* Subroutines used for code generation on o386, this is, obfuscated i386 backend.
   Copyright (C) Free Software Foundation, Inc.
   Contributed by David Guillen Fandos <david@davidgf.net>
     Many stuff borrowed from moxie backend, thanks to Anthony Green

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "rtl.h"
#include "tree.h"
#include "tm_p.h"
#include "regs.h"
#include "hard-reg-set.h"
#include "insn-config.h"
#include "conditions.h"
#include "output.h"
#include "insn-codes.h"
#include "insn-attr.h"
#include "flags.h"
#include "except.h"
#include "function.h"
#include "recog.h"
#include "expr.h"
#include "optabs.h"
#include "diagnostic-core.h"
#include "toplev.h"
#include "basic-block.h"
#include "ggc.h"
#include "target.h"
#include "target-def.h"
#include "common/common-target.h"
#include "langhooks.h"
#include "reload.h"
#include "cgraph.h"
#include "gimple.h"
#include "dwarf2.h"
#include "df.h"
#include "tm-constrs.h"
#include "params.h"
#include "cselib.h"
#include "debug.h"
#include "sched-int.h"
#include "sbitmap.h"
#include "fibheap.h"
#include "opts.h"
#include "diagnostic.h"


/* Per-function machine data.  */
struct GTY(()) machine_function
 {
   /* Number of bytes saved on the stack for callee saved registers.  */
   int callee_saved_reg_size;

   /* Number of bytes saved on the stack for local variables.  */
   int local_vars_size;

   /* The sum of 2 sizes: locals vars and padding byte for saving the
    * registers.  Used in expand_prologue () and expand_epilogue().  */
   int size_for_adjusting_sp;
 };
 
#undef TARGET_OPTION_OVERRIDE
#define TARGET_OPTION_OVERRIDE o386_option_override
/* The TARGET_OPTION_OVERRIDE worker.
   All this curently does is set init_machine_status.  */
static struct machine_function *
o386_init_machine_status (void)
{
  return ggc_alloc_cleared_machine_function ();
}
static void
o386_option_override (void)
{
  /* Set the per-function-data initializer.  */
  init_machine_status = o386_init_machine_status;
}

#define LOSE_AND_RETURN(msgid, x)		\
  do						\
    {						\
      o386_operand_lossage (msgid, x);		\
      return;					\
    } while (0)

static void
o386_operand_lossage (const char *msgid, rtx op)
{
  debug_rtx (op);
  output_operand_lossage ("%s", msgid);
}

/* This routine prints an operand into the assembler output. The formating
   has to be coherent with what 'as' (and other binutils tools) expect.
   As we use the regular x86 tools we are going to output standard gas assembly */

void
o386_print_operand (FILE *file, rtx x, int code)
{
  rtx operand = x;

  /* New code entries should just be added to the switch below.  If
     handling is finished, just return.  If handling was just a
     modification of the operand, the modified operand should be put in
     "operand", and then do a break to let default handling
     (zero-modifier) output the operand.  */

  switch (code)
    {
    case 0:
      /* No code, print as usual.  */
      break;

    default:
      LOSE_AND_RETURN ("invalid operand modifier letter", x);
    }

  /* Print an operand as without a modifier letter.  */
  switch (GET_CODE (operand))
    {
    case REG:
      fprintf (file, "%s", reg_names[REGNO (operand)]);
      return;

    case MEM:
      output_address (XEXP (operand, 0));
      return;

    default:
      /* No need to handle all strange variants, let output_addr_const do it for us.  */
      if (CONST_INT_P (operand))
        putc('$',file);
      if (CONSTANT_P (operand)) {
        output_addr_const (file, operand);
        return;
      }

      LOSE_AND_RETURN ("unexpected operand", x);
    }
}

/* This function prints memory operands. It should be able to handle all the memory
   operands allowed by memory constraints. This is, if we allow register+offset and
   register flavors for a memory operand, we need to handle those cases here. It is
   up to us (well, to the arch) to decide which modes we want to allow.
   Of course, for o386 we are using the i386 addressing mode compatible with binutils. */

void
o386_print_operand_address (FILE *file, rtx x)
{
  switch (GET_CODE (x))
    {
    case REG:
      fprintf (file, "(%s)", reg_names[REGNO (x)]);
      break;
      
    case PLUS:
      switch (GET_CODE (XEXP (x, 1)))
	{
	case CONST_INT:
	  fprintf (file, "%ld(%s)", 
		   INTVAL(XEXP (x, 1)), reg_names[REGNO (XEXP (x, 0))]);
	  break;
	case SYMBOL_REF:
	  output_addr_const (file, XEXP (x, 1));
	  fprintf (file, "(%s)", reg_names[REGNO (XEXP (x, 0))]);
	  break;
	case CONST:
	  {
	    rtx plus = XEXP (XEXP (x, 1), 0);
	    if (GET_CODE (XEXP (plus, 0)) == SYMBOL_REF 
		&& CONST_INT_P (XEXP (plus, 1)))
	      {
		output_addr_const(file, XEXP (plus, 0));
		fprintf (file,"+%ld(%s)", INTVAL (XEXP (plus, 1)),
			 reg_names[REGNO (XEXP (x, 0))]);
	      }
	    else
	      abort();
	  }
	  break;
	default:
	  abort();
	}
      break;

    default:
      output_addr_const (file, x);
      break;
    }
}



/*int
compute_frame_size (int size, long * p_reg_saved)
{
  int s = 0, regno;

  // Save callee-saved registers. 
  for (regno = 0; regno < FIRST_PSEUDO_REGISTER; regno++)
    if (df_regs_ever_live_p(regno) && (! call_used_regs[regno]))
      s += 4;

  return (size + s + current_function_outgoing_args_size);
}*/

/* Compute the size of the local area and the size to be adjusted by the
 * prologue and epilogue. */

static void
o386_compute_frame (void)
{
  /* For aligning the local variables. */
  int stack_alignment = STACK_BOUNDARY / BITS_PER_UNIT;
  int padding_locals;
  int regno;

  /* Padding needed for each element of the frame.  */
  cfun->machine->local_vars_size = get_frame_size ();

  /* Align to the stack alignment. */
  padding_locals = cfun->machine->local_vars_size % stack_alignment;
  if (padding_locals)
    padding_locals = stack_alignment - padding_locals;

  cfun->machine->local_vars_size += padding_locals;

  cfun->machine->callee_saved_reg_size = 0;

  /* Save callee-saved registers.  */
  for (regno = 0; regno < FIRST_PSEUDO_REGISTER; regno++)
    if (df_regs_ever_live_p(regno) && (! call_used_regs[regno]))
      cfun->machine->callee_saved_reg_size += 4;

  cfun->machine->size_for_adjusting_sp = 
    crtl->args.pretend_args_size
    + cfun->machine->local_vars_size 
    + (ACCUMULATE_OUTGOING_ARGS ? crtl->outgoing_args_size : 0);
}

int
o386_initial_elimination_offset (int from, int to)
{
  /*int ret;
  
  if ((from) == FRAME_POINTER_REGNUM && (to) == HARD_FRAME_POINTER_REGNUM)
    {
      // Compute this since we need to use cfun->machine->local_vars_size.  
      o386_compute_frame ();
      ret = -cfun->machine->callee_saved_reg_size;
    }
  else if ((from) == ARG_POINTER_REGNUM && (to) == HARD_FRAME_POINTER_REGNUM)
    ret = 0x00;
  else
    abort ();

  return ret;*/

  if ((from) == FRAME_POINTER_REGNUM && (to) == HARD_FRAME_POINTER_REGNUM) {
    // Frame pointer is hard frame pointer! :D
    return 0x0;
  }
  else if ((from) == ARG_POINTER_REGNUM && (to) == HARD_FRAME_POINTER_REGNUM) {
    // Arg pointer is at 4 + 4 (ret@ + HFP) + callee-saved distance
    o386_compute_frame();
    return cfun->machine->callee_saved_reg_size + 4 + 4;
  }
  else
    abort();
  
}


/* Stack format:

Callee function:  |-------------------------|  <- ESP
                  |  Local variables        |
                  |-------------------------|  <- EBP
                  |  Hard frame pointer     |
                  |-------------------------|
                  |  Callee saved regs      |
                  |-------------------------|
                  |   Ret addr              |
Caller function:  |-------------------------|  <- ARGS pointer
                  |   Param 0 (leftmost)    |
                  |   Param 1               |
                  |     ...                 |
                  |   Param N-1             |
                  |-------------------------|
                  | Caller saved registers  |
                  |-------------------------|
*/

void
o386_expand_prologue ()
{
  int regno;
  rtx insn;

  o386_compute_frame ();

  /* Save callee-saved registers.  */
  for (regno = 0; regno < FIRST_PSEUDO_REGISTER; regno++) {
    if (df_regs_ever_live_p(regno) && (! call_used_regs[regno])) {
      insn = emit_insn (gen_movsi_push (gen_rtx_REG (Pmode, regno)));
      RTX_FRAME_RELATED_P (insn) = 1;
    }
  }

  /* Now save old frame pointer (needed?) */
  insn = emit_insn (gen_movsi_push (gen_rtx_REG (Pmode, HARD_FRAME_POINTER_REGNUM)));
  RTX_FRAME_RELATED_P (insn) = 1;

  /* Now set the frame pointer as stack top */ 
  insn = emit_insn (gen_movsi (gen_rtx_REG (Pmode, HARD_FRAME_POINTER_REGNUM), stack_pointer_rtx));
  RTX_FRAME_RELATED_P (insn) = 1;

  /* Now move stack pointer to allocate local vars */
  if (cfun->machine->size_for_adjusting_sp > 0) {
    insn = emit_insn (gen_addsi3 (stack_pointer_rtx, stack_pointer_rtx, GEN_INT (-cfun->machine->size_for_adjusting_sp)));
    RTX_FRAME_RELATED_P (insn) = 1;
  }
}

void
o386_expand_epilogue ()
{
  int regno;
  rtx insn;

  /* To restore the frame and stack it's quite simple 
     just move the EBP to ESP to deallocate all local vars
     Then pop EBP to restore original FP and finally pop
     all saved regs.                                      */

  insn = emit_insn (gen_movsi (stack_pointer_rtx, gen_rtx_REG (Pmode, HARD_FRAME_POINTER_REGNUM)));
  RTX_FRAME_RELATED_P (insn) = 1;

  insn = emit_insn (gen_movsi_pop (gen_rtx_REG (Pmode, HARD_FRAME_POINTER_REGNUM)));
  RTX_FRAME_RELATED_P (insn) = 1;


  /* Save callee-saved registers.  */
  for (regno = FIRST_PSEUDO_REGISTER-1; regno >= 0; --regno) {
    if (df_regs_ever_live_p(regno) && (! call_used_regs[regno])) {
      insn = emit_insn (gen_movsi_pop (gen_rtx_REG (Pmode, regno)));
      RTX_FRAME_RELATED_P (insn) = 1;
    }
  }

  insn = emit_jump_insn (gen_returner ());
  RTX_FRAME_RELATED_P (insn) = 1;
}






#undef  TARGET_FUNCTION_VALUE
#define TARGET_FUNCTION_VALUE         o386_function_value
#undef  TARGET_FUNCTION_ARG_ADVANCE
#define TARGET_FUNCTION_ARG_ADVANCE   o386_function_arg_advance
#undef  TARGET_FUNCTION_ARG
#define TARGET_FUNCTION_ARG           o386_function_arg
#undef  TARGET_RETURN_IN_MEMORY
#define TARGET_RETURN_IN_MEMORY       o386_return_in_memory
#undef  TARGET_FUNCTION_VALUE_REGNO_P
#define TARGET_FUNCTION_VALUE_REGNO_P o386_function_value_regno_p


/* Define how to find the value returned by a function.
   VALTYPE is the data type of the value (as a tree).
   If the precise function being called is known, FUNC is its
   FUNCTION_DECL; otherwise, FUNC is 0.  

   We always return values in register eax for x86 */

static rtx
o386_function_value (const_tree valtype,
                      const_tree fntype_or_decl ATTRIBUTE_UNUSED,
                      bool outgoing ATTRIBUTE_UNUSED)
{
  return gen_rtx_REG (TYPE_MODE (valtype), O386_EAX);
}

#define O386_FUNCTION_ARG_SIZE(MODE, TYPE)     \
  ((MODE) != BLKmode ? GET_MODE_SIZE (MODE)     \
   : (unsigned) int_size_in_bytes (TYPE))

static void
o386_function_arg_advance (cumulative_args_t cum_v, enum machine_mode mode,
                            const_tree type, bool named ATTRIBUTE_UNUSED)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);

  *cum += (3 + O386_FUNCTION_ARG_SIZE(mode,type))/4;
}

static rtx
o386_function_arg (cumulative_args_t cum_v, enum machine_mode omode,
                   const_tree type, bool named)
{
	return NULL_RTX;
}

static bool
o386_return_in_memory (const_tree type, const_tree fntype ATTRIBUTE_UNUSED)
{
  const HOST_WIDE_INT size = int_size_in_bytes (type);
  return (size == -1 || size > UNITS_PER_WORD);
}

static bool
o386_function_value_regno_p (const unsigned int regno)
{
  return (regno == O386_EAX);
}


struct gcc_target targetm = TARGET_INITIALIZER;
#include "gt-i386.h"

