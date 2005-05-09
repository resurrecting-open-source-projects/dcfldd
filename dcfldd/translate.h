/* $Id$
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

#ifndef TRANSLATE_H
#define TRANSLATE_H

#include "dcfldd.h"
#include <sys/types.h>

extern unsigned char newline_character;
extern unsigned char space_character;

extern unsigned char trans_table[];
extern unsigned char const ascii_to_ebcdic[];
extern unsigned char const ascii_to_ibm[];
extern unsigned char const ebcdic_to_ascii[];

extern void translate_buffer(unsigned char *, size_t);
extern void apply_translations(void);

#endif /* TRANSLATE_H */
