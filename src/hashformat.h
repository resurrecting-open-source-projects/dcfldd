/* $Id: hashformat.h,v 1.1 2005/05/14 23:20:30 harbourn Exp $
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

#ifndef HASH_FORMAT_H
#define HASH_FORMAT_H

#include "dcfldd.h"
#include "hash.h"
#include <stdio.h>
#include <sys/types.h>

typedef enum {
    FMT_STRING,
    FMT_WINDOW_START,
    FMT_WINDOW_END,
    FMT_WINBLK_START,  /* window offsets / blocksize */
    FMT_WINBLK_END,
    FMT_HASH,
    FMT_ALGORITHM
} fmtatom_t;

#define FMTATOMOP_ARGS FILE *stream, off_t wina, off_t winb, size_t blksize, char *alg, void *data

typedef void (fmtatom_op_t)(FMTATOMOP_ARGS);

#ifndef VARIABLE_HOOK
#define VARIABLE_HOOK '#'
#endif

typedef struct format_s {
    struct format_s *next;
    fmtatom_t type;
    fmtatom_op_t *op;
    void *data;  /* optional */
} format_t;

extern format_t *hashformat;
extern format_t *totalhashformat;

extern void print_fmt(format_t *, FMTATOMOP_ARGS);
extern format_t *parse_hashformat(char *);

#endif /* HASH_FORMAT_H */
