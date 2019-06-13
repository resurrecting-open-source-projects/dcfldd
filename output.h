/* $Id: output.h,v 1.4 2005/05/15 20:15:28 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2008                        Dave <dloveall@users.sf.net>

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

#ifndef OUTPUT_H
#define OUTPUT_H

#include "dcfldd.h"
#include <sys/types.h>
#include "split.h"

typedef enum
{
    NONE,
    SINGLE_FILE,
    SPLIT_FILE,
    STREAM
} outputtype_t;

typedef struct outputlist_s
{
    struct outputlist_s *next;
    outputtype_t type;
    FILE *stream;
    union {
        int fd;
        split_t *split;
    } data;
} outputlist_t;

extern outputlist_t *outputlist;

extern void open_output(char *);
extern void open_output_pipe(char *);
extern void outputlist_add(outputtype_t, ...);
extern int outputlist_write(const char *, size_t);

#endif /* OUTPUT_H */
