/* Target Definitions for o386 (obfuscated i386 backend)
   Copyright (C) 2008, 2009, 2010  Free Software Foundation, Inc.
   Contributed by David Guillen Fandos <david@davidgf.net>
     Many stuff borrowed from moxie backend, thanks to Anthony Green

   This file is part of GCC.

   GCC is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3, or (at your
   option) any later version.

   GCC is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with GCC; see the file COPYING3.  If not see
   <http://www.gnu.org/licenses/>.  */

#ifndef GCC_O386_H
#define GCC_O386_H


// 386 specific stuff
#define TARGET_DEFAULT 0
#define TARGET_MACHO   0

#define ASM_ATT 0
#define ASSEMBLER_DIALECT ASM_ATT

/* Basic machine description */

#define INT_TYPE_SIZE 32
#define SHORT_TYPE_SIZE 16
#define LONG_TYPE_SIZE 32
#define LONG_LONG_TYPE_SIZE 64
#define FLOAT_TYPE_SIZE 32
#define DOUBLE_TYPE_SIZE 64
#define LONG_DOUBLE_TYPE_SIZE 64

#define DEFAULT_SIGNED_CHAR 1




/* Machine register description */

enum reg_class
{
  NO_REGS,
  GENERAL_REGS,  // GPR registers
  CC_REGS,       // EFLAGS register

  AREG, BREG, CREG, DREG,  // Q regs

  ALL_REGS,
  LIM_REG_CLASSES
};

#define REG_CLASS_CONTENTS \
{ { 0x00000000 }, /* Empty */    \
  { 0x000003FF }, /* eax..esp + argp + fp */ \
  { 0x00000400 }, /* eflags */   \
   \
  { 0x00000001 }, /* EAX */ \
  { 0x00000008 }, /* EBX */ \
  { 0x00000004 }, /* ECX */ \
  { 0x00000002 }, /* EDX */ \
   \
  { 0x000007FF }  /* All */      \
}

#define N_REG_CLASSES LIM_REG_CLASSES

#define REG_CLASS_NAMES {\
    "NO_REGS", \
    "GENERAL_REGS", \
    "CC_REGS", \
    "AREG", "BREG", "CREG", "DREG", \
    "ALL_REGS" }

#define O386_EAX      0
#define O386_EDX      1
#define O386_ECX      2
#define O386_EBX      3 
#define O386_ESI      4
#define O386_EDI      5
#define O386_EBP      6
#define O386_ESP      7
#define O386_ARG      8
#define O386_QFP      9
#define O386_EFLAGS  10

#define REGISTER_NAMES { \
"%eax","%edx","%ecx","%ebx","%esi","%edi","%ebp","%esp","arg","qfp","eflags" \
}
#define REGISTER_NAMES_BYTE { \
"%al","%dl","%cl","%bl","NA_si","NA_di","NA_bp","NA_sp","arg","qfp","eflags" \
}
#define REGISTER_NAMES_WORD { \
"%ax","%dx","%cx","%bx","%si","%di","%bp","%sp","arg","qfp","eflags" \
}

#define FIXED_REGISTERS { \
 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 \
}

#define CALL_USED_REGISTERS { \
 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1    \
}

#define FIRST_PSEUDO_REGISTER 11

/* Avoid eflags copy, it's not comfortable */
#define AVOID_CCMODE_COPIES 1

/* A C expression that is nonzero if it is permissible to store a
   value of mode MODE in hard register number REGNO (or in several
   registers starting with that one).  All gstore registers are 
   equivalent, so we can set this to 1.  */
#define HARD_REGNO_MODE_OK(R,M) o386_hard_regno_mode_ok(R,M)

/* A C expression whose value is a register class containing hard
   register REGNO.  */
#define REGNO_REG_CLASS(R) \
  (R == O386_EAX ? AREG : \
  (R == O386_EBX ? BREG : \
  (R == O386_ECX ? CREG : \
  (R == O386_EDX ? DREG : \
   ((R < O386_EFLAGS) ? GENERAL_REGS : CC_REGS)))))

/* A C expression for the number of consecutive hard registers,
   starting at register number REGNO, required to hold a value of mode
   MODE.  */
#define HARD_REGNO_NREGS(REGNO, MODE)			   \
  ((GET_MODE_SIZE (MODE) + UNITS_PER_WORD - 1)		   \
   / UNITS_PER_WORD)

/* A C expression that is nonzero if a value of mode MODE1 is
   accessible in mode MODE2 without copying.  */
#define MODES_TIEABLE_P(MODE1, MODE2) 1


/* The Overall Framework of an Assembler File */
// Copied from Moxie, need to review

#undef  ASM_SPEC
#undef  ASM_COMMENT_START
#define ASM_COMMENT_START "#"
#undef  ASM_APP_ON
#define ASM_APP_ON ""
#undef  ASM_APP_OFF
#define ASM_APP_OFF ""

#define FILE_ASM_OP     "\t.file\n"

/* Switch to the text or data segment.  */
#define TEXT_SECTION_ASM_OP  "\t.text"
#define DATA_SECTION_ASM_OP  "\t.data"

/* Assembler Commands for Alignment */

#define ASM_OUTPUT_ALIGN(STREAM,POWER) \
	fprintf (STREAM, "\t.p2align\t%d\n", POWER);


/* Operand print format (implemented in .c file) */
#define PRINT_OPERAND(STREAM, X, CODE) o386_print_operand (STREAM, X, CODE)
#define PRINT_OPERAND_ADDRESS(STREAM ,X) o386_print_operand_address (STREAM, X)

/* Output and Generation of Labels */

#undef  GLOBAL_ASM_OP
#define GLOBAL_ASM_OP "\t.global\t"


/* Passing Arguments in Registers */

/* A C type for declaring a variable that is used as the first
   argument of `FUNCTION_ARG' and other related values.  */
#define CUMULATIVE_ARGS unsigned int

/* If defined, the maximum amount of space required for outgoing arguments
   will be computed and placed into the variable
   `current_function_outgoing_args_size'.  No space will be pushed
   onto the stack for each call; instead, the function prologue should
   increase the stack frame size by this amount.  */
#define ACCUMULATE_OUTGOING_ARGS 0

/* A C statement (sans semicolon) for initializing the variable CUM
   for the state at the beginning of the argument list.  
   For x86 we don't pass arguments in registers so far.  */
#define INIT_CUMULATIVE_ARGS(CUM,FNTYPE,LIBNAME,FNDECL,N_NAMED_ARGS) 






/* How Scalar Function Values Are Returned */

/* STACK AND CALLING */

/* Define this macro if pushing a word onto the stack moves the stack
   pointer to a smaller address.  */
#define STACK_GROWS_DOWNWARD

#define INITIAL_FRAME_POINTER_OFFSET(DEPTH) (DEPTH) = 0

/* Offset from the frame pointer to the first local variable slot to
   be allocated.  */
#define STARTING_FRAME_OFFSET 0

/* Define this if the above stack space is to be considered part of the
   space allocated by the caller.  */
#define OUTGOING_REG_PARM_STACK_SPACE(FNTYPE) 1
#define STACK_PARMS_IN_REG_PARM_AREA

/* Define this if it is the responsibility of the caller to allocate
   the area reserved for arguments passed in registers.  */
#define REG_PARM_STACK_SPACE(FNDECL) (6 * UNITS_PER_WORD)

/* Offset from the argument pointer register to the first argument's
   address.  On some machines it may depend on the data type of the
   function.  */
#define FIRST_PARM_OFFSET(F) 0

/* Define this macro to nonzero value if the addresses of local variable slots
   are at negative offsets from the frame pointer.  */
#define FRAME_GROWS_DOWNWARD 1

/* Define this macro as a C expression that is nonzero for registers that are
   used by the epilogue or the return pattern.  The stack and frame
   pointer registers are already assumed to be used as needed.  */
#define EPILOGUE_USES(R) 0

/* A C expression whose value is RTL representing the location of the
   incoming return address at the beginning of any function, before
   the prologue.  */
#define INCOMING_RETURN_ADDR_RTX					\
  gen_frame_mem (Pmode,							\
		 plus_constant (stack_pointer_rtx, UNITS_PER_WORD))

/* Describe how we implement __builtin_eh_return.  */
#define EH_RETURN_DATA_REGNO(N)	((N) < 4 ? (N+2) : INVALID_REGNUM)

/* Store the return handler into the call frame.  */
#define EH_RETURN_HANDLER_RTX						\
  gen_frame_mem (Pmode,							\
		 plus_constant (frame_pointer_rtx, UNITS_PER_WORD))


#define TARGET_LIBCALL_VALUE o386_libcall_value



/* Storage Layout */

#define BITS_BIG_ENDIAN 0
#define BYTES_BIG_ENDIAN 1
#define WORDS_BIG_ENDIAN 1

/* Alignment required for a function entry point, in bits.  */
#define FUNCTION_BOUNDARY 16

/* Define this macro as a C expression which is nonzero if accessing
   less than a word of memory (i.e. a `char' or a `short') is no
   faster than accessing a word of memory.  */
#define SLOW_BYTE_ACCESS 1

/* Number of storage units in a word; normally the size of a
   general-purpose register, a power of two from 1 or 8.  */
#define UNITS_PER_WORD 4

/* Define this macro to the minimum alignment enforced by hardware
   for the stack pointer on this machine.  The definition is a C
   expression for the desired alignment (measured in bits).  */
#define STACK_BOUNDARY 32

/* Normal alignment required for function parameters on the stack, in
   bits.  All stack parameters receive at least this much alignment
   regardless of data type.  */
#define PARM_BOUNDARY 32

/* Alignment of field after `int : 0' in a structure.  */
#define EMPTY_FIELD_BOUNDARY  32

/* No data type wants to be aligned rounder than this.  */
#define BIGGEST_ALIGNMENT 32

/* The best alignment to use in cases where we have a choice.  */
#define FASTEST_ALIGNMENT 32

/* Every structures size must be a multiple of 8 bits.  */
#define STRUCTURE_SIZE_BOUNDARY 8


/* Look at the fundamental type that is used for a bit-field and use 
   that to impose alignment on the enclosing structure.
   struct s {int a:8}; should have same alignment as "int", not "char".  */
#define	PCC_BITFIELD_TYPE_MATTERS	1

/* Largest integer machine mode for structures.  If undefined, the default
   is GET_MODE_SIZE(DImode).  */
#define MAX_FIXED_MODE_SIZE 32

/* Make strings word-aligned so strcpy from constants will be faster.  */
#define CONSTANT_ALIGNMENT(EXP, ALIGN)  \
  ((TREE_CODE (EXP) == STRING_CST	\
    && (ALIGN) < FASTEST_ALIGNMENT)	\
   ? FASTEST_ALIGNMENT : (ALIGN))

/* Make arrays of chars word-aligned for the same reasons.  */
#define DATA_ALIGNMENT(TYPE, ALIGN)		\
  (TREE_CODE (TYPE) == ARRAY_TYPE		\
   && TYPE_MODE (TREE_TYPE (TYPE)) == QImode	\
   && (ALIGN) < FASTEST_ALIGNMENT ? FASTEST_ALIGNMENT : (ALIGN))
     
/* Set this nonzero if move instructions will actually fail to work
   when given unaligned data.  */
#define STRICT_ALIGNMENT 0

/* Generating Code for Profiling */
#define FUNCTION_PROFILER(FILE,LABELNO) (abort (), 0)

/* Trampolines for Nested Functions.  */
#define TRAMPOLINE_SIZE (2 + 6 + 6 + 2 + 2 + 6)

/* Alignment required for trampolines, in bits.  */
#define TRAMPOLINE_ALIGNMENT 32

/* An alias for the machine mode for pointers.  */
#define Pmode         SImode

/* An alias for the machine mode used for memory references to
   functions being called, in `call' RTL expressions.  */
#define FUNCTION_MODE SImode

/* The register number of the stack pointer register, which must also
   be a fixed register according to `FIXED_REGISTERS'.  */
#define STACK_POINTER_REGNUM O386_ESP

/* The register number of the frame pointer register, which is used to
   access automatic variables in the stack frame.  */
#define FRAME_POINTER_REGNUM O386_QFP

/* The register number of the arg pointer register, which is used to
   access the function's argument list.  */
#define ARG_POINTER_REGNUM O386_ARG

#define HARD_FRAME_POINTER_REGNUM O386_EBP

#define ELIMINABLE_REGS  \
{{ FRAME_POINTER_REGNUM, HARD_FRAME_POINTER_REGNUM },  \
 { ARG_POINTER_REGNUM,   HARD_FRAME_POINTER_REGNUM }}			

/* This macro is similar to `INITIAL_FRAME_POINTER_OFFSET'.  It
   specifies the initial difference between the specified pair of
   registers.  This macro must be defined if `ELIMINABLE_REGS' is
   defined.  */
#define INITIAL_ELIMINATION_OFFSET(FROM, TO, OFFSET)			\
  do {									\
    (OFFSET) = o386_initial_elimination_offset ((FROM), (TO));		\
  } while (0)


/* A C expression that is nonzero if REGNO is the number of a hard
   register in which function arguments are sometimes passed.  */
#define FUNCTION_ARG_REGNO_P(r) (0)

/* A macro whose definition is the name of the class to which a valid
   base register must belong.  A base register is one used in an
   address which is the register value plus a displacement.  */
#define BASE_REG_CLASS GENERAL_REGS

#define INDEX_REG_CLASS NO_REGS

#define HARD_REGNO_OK_FOR_BASE_P(NUM) \
  ((unsigned) (NUM) < FIRST_PSEUDO_REGISTER \
   && (REGNO_REG_CLASS(NUM) == GENERAL_REGS \
       || (NUM) == HARD_FRAME_POINTER_REGNUM))

/* A C expression which is nonzero if register number NUM is suitable
   for use as a base register in operand addresses.  */
//#ifdef REG_OK_STRICT
//#define REGNO_OK_FOR_BASE_P(NUM) (HARD_REGNO_OK_FOR_BASE_P(NUM) || HARD_REGNO_OK_FOR_BASE_P(reg_renumber[(NUM)]))
//#else
//#define REGNO_OK_FOR_BASE_P(NUM) ((NUM) >= FIRST_PSEUDO_REGISTER || HARD_REGNO_OK_FOR_BASE_P(NUM))
//#endif
#define REGNO_OK_FOR_BASE_P(NUM) 1

#define REGNO_OK_FOR_INDEX_P(REGNO) 0




/* The maximum number of bytes that a single instruction can move
   quickly between memory and registers or between two memory
   locations.  */
#define MOVE_MAX 4

#define TRULY_NOOP_TRUNCATION(op,ip) 1

/* All load operations zero extend.  */
#define LOAD_EXTEND_OP(MEM) ZERO_EXTEND

/* A number, the maximum number of registers that can appear in a
   valid memory address.  */
#define MAX_REGS_PER_ADDRESS 1

/* An alias for a machine mode name.  This is the machine mode that
   elements of a jump-table should have.  */
#define CASE_VECTOR_MODE SImode


#define LEGITIMIZE_RELOAD_ADDRESS(X,MODE,OPNUM,TYPE,IND_L,WIN)          \
  do {                                                                  \
    rtx new_x = o386_legitimize_reload_address (&(X),MODE);             \
    if (new_x != NULL_RTX)                                              \
      {                                                                 \
        X = new_x;                                                      \
        goto WIN;                                                       \
      }                                                                 \
  } while (0)


#define TARGET_CPU_CPP_BUILTINS()

#define TARGET_SUBTARGET_ISA_DEFAULT 0

#define SUBTARGET_CPP_SPEC  "-D__i386__"

#endif

