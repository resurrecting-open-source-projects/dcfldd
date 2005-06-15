/* $Id: util.h,v 1.5 2005/05/15 13:18:27 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright (C) 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* GNU dd originally written by Paul Rubin, David MacKenzie, and Stuart Kemp. */

#ifndef UTIL_H
#define UTIL_H

#include "dcfldd.h"
#include "config.h"

#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>

extern int buggy_lseek_support(int);
extern void skip(int, char *, uintmax_t, size_t, unsigned char *);
extern unsigned char *swab_buffer(unsigned char *, size_t *);
extern void time_left(char *, size_t, int);
extern int bit_count(register unsigned int);
extern void replace_escapes(char *);
extern FILE *popen2(const char *, const char *);
extern pclose2(FILE *);

#if (!HAVE_DECL_STRNDUP)
extern char *strndup(const char *, size_t);
#endif

#endif /* UTIL_H */
