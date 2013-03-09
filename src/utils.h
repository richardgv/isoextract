/*
 * isoextract (development version)
 * https://github.com/richardgv/isoextract/
 *
 * Copyright 2013 Richard Grenville <https://github.com/richardgv>
 * License: MIT
 */

/**
 * @file utils.h
 * @brief Private headers of utils.c .
 */

#include "common.h"

#include <errno.h>

// Stolen from intprops.h from coreutils-8.21

/* True if the arithmetic type T is signed.  */
#define TYPE_SIGNED(t) (! ((t) 0 < (t) -1))

/* Return 1 if the __typeof__ keyword works.  This could be done by
   'configure', but for now it's easier to do it by hand.  */
#if 2 <= __GNUC__ || 0x5110 <= __SUNPRO_C
# define _GL_HAVE___TYPEOF__ 1
#else
# define _GL_HAVE___TYPEOF__ 0
#endif

/* Return 1 if the integer type or expression T might be signed.  Return 0
   if it is definitely unsigned.  This macro does not evaluate its argument,
   and expands to an integer constant expression.  */
#if _GL_HAVE___TYPEOF__
# define _GL_SIGNED_TYPE_OR_EXPR(t) TYPE_SIGNED (__typeof__ (t))
#else
# define _GL_SIGNED_TYPE_OR_EXPR(t) 1
#endif

/* Bound on length of the string representing an unsigned integer
   value representable in B bits.  log10 (2.0) < 146/485.  The
   smallest value of B where this bound is not tight is 2621.  */
#define INT_BITS_STRLEN_BOUND(b) (((b) * 146 + 484) / 485)

/* Bound on length of the string representing an integer type or expression T.
   Subtract 1 for the sign bit if T is signed, and then add 1 more for
   a minus sign if needed.

   Because _GL_SIGNED_TYPE_OR_EXPR sometimes returns 0 when its argument is
   signed, this macro may overestimate the true bound by one byte when
   applied to unsigned types of size 2, 4, 16, ... bytes.  */
#define INT_STRLEN_BOUND(t)                                     \
  (INT_BITS_STRLEN_BOUND (sizeof (t) * CHAR_BIT                 \
                          - _GL_SIGNED_TYPE_OR_EXPR (t))        \
   + _GL_SIGNED_TYPE_OR_EXPR (t))


/**
 * @brief Return a const string representation of errno.
 */
static inline const char *dumpstr_errno(void) {
  switch (errno) {
    CASEMNAMERET(EACCES);
    CASEMNAMERET(EEXIST);
    CASEMNAMERET(EMLINK);
    CASEMNAMERET(ENOSPC);
    CASEMNAMERET(EROFS);
  }

  return NULL;
}
