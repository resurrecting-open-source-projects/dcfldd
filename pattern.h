/* $Id: pattern.h,v 1.3 2005/05/13 18:52:06 harbourn Exp $
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

#ifndef PATTERN_H
#define PATTERN_H

#include "dcfldd.h"
#include <sys/types.h>

extern char *pattern;
extern size_t pattern_len;
extern int input_from_pattern;

extern char *make_pattern(char *);
extern void replicate_pattern(char *, char *, size_t);

#endif /* PATTERN_H */
