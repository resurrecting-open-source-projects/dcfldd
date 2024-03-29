/* $Id: split.h,v 1.3 2005/05/13 18:52:06 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */
/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2022                        Tibor Szolnoki <szolnoki.tibor@gmail.com>

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
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.  */

/* GNU dd originally written by Paul Rubin, David MacKenzie, and Stuart Kemp. */

#ifndef SPLIT_H
#define SPLIT_H

#include "dcfldd.h"
#include <sys/types.h>

typedef struct
{
    int currfd;
    off_t max_bytes; /* The split size */
    off_t total_bytes; /* Total Bytes written sofar */
    off_t curr_bytes; /* Bytes written to current split file */
    char *name;
    char *format;
} split_t;

extern int split_write(split_t *, const char *, size_t, int diffwr);

#endif /* SPLIT_H */
