;; Constraint definitions for o386 (obfuscated i386 backend)
;; Copyright (C) 2014 Free Software Foundation, Inc.
;; Contributed by David Guillen Fandos <david@davidgf.net>

;; This file is part of GCC.

;; GCC is free software; you can redistribute it and/or modify it
;; under the terms of the GNU General Public License as published
;; by the Free Software Foundation; either version 3, or (at your
;; option) any later version.

;; GCC is distributed in the hope that it will be useful, but WITHOUT
;; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
;; or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
;; License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GCC; see the file COPYING3.  If not see
;; <http://www.gnu.org/licenses/>.

;; -------------------------------------------------------------------------
;; Constraints
;; -------------------------------------------------------------------------

;; Immediate ranges

(define_constraint "K"
  "Signed 8-bit integer constant."
  (and (match_code "const_int")
       (match_test "IN_RANGE (ival, -128, 127)")))

(define_constraint "U"
  "Unsigned 8-bit integer constant."
  (and (match_code "const_int")
       (match_test "IN_RANGE (ival, 0, 256)")))

(define_constraint "C"
  "Signed 32-bit integer constant."
  (ior
    (and (match_code "const_int")
         (match_test "IN_RANGE (ival, -2147483648, 2147483647)"))
    (match_code "symbol_ref")
  )
)

;; Addresses

(define_constraint "A"
    "A memory address, either absolute reference or register"
    (and (match_code "mem")
         (ior (match_test "GET_CODE (XEXP (op, 0)) == SYMBOL_REF")
              (match_test "GET_CODE (XEXP (op, 0)) == LABEL_REF")
              (match_test "GET_CODE (XEXP (op, 0)) == CONST")
              (match_test "REG_P (XEXP (op, 0))")
              (match_test "GET_CODE (XEXP (op, 0)) == PLUS")
         )
    )
)

(define_constraint "O"
  "The constant zero"
  (and (match_code "const_int")
       (match_test "ival == 0")))

;; x86 registers

(define_register_constraint "a" "AREG"
 "The @code{a} register.")

(define_register_constraint "b" "BREG"
 "The @code{b} register.")

(define_register_constraint "c" "CREG"
 "The @code{c} register.")

(define_register_constraint "d" "DREG"
 "The @code{d} register.")



