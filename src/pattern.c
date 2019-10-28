/* $Id: pattern.c,v 1.3 2005/05/13 18:52:06 harbourn Exp $
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

#include "dcfldd.h"
#include <sys/types.h>

/* Pattern to be written out */
char *pattern;
size_t pattern_len;
int input_from_pattern;


char *make_pattern(char *pattern)
{
    size_t plen, numbytes, i;
    char *buffer;

    plen = strlen(pattern);

    if (plen == 0 || plen % 2 != 0)
        return NULL;

    numbytes = plen / 2;
    buffer = malloc(numbytes);

    for (i = 0; i < numbytes; i++) {
        char tmpstring[3];
        int byteval;
        strncpy(tmpstring, &pattern[i*2], 2);
        tmpstring[2] = '\0';
        byteval = hex2char(tmpstring);

        if (byteval == -1) {
            free(buffer);
            return NULL;
        }
        buffer[i] = (char)byteval;
    }
    pattern_len = numbytes;

    return buffer;
}

void replicate_pattern(char *pattern, char *buffer, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++)
        buffer[i] = pattern[i % pattern_len];
}


