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

#include "dcfldd.h"
#include "split.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "full-write.h"
#include "log.h"


/* for portability, use these arrays for referencing numbers and letters */
static char *numbers = "0123456789";
#define NUM_NUMBERS 10
static char *letters = "abcdefghijklmnopqrstuvwxyz";
#define NUM_LETTERS 26

static char *getext(char *, int);
static int maxsplits(char *);

/* Generate a split file extension string based on
 * the specified format string and a given number
 */
static char *getext(char *fmt, int num)
{
    int fmtlen = strlen(fmt);
    int i;
    char *retval;
    
    assert(fmtlen > 0);

    retval = malloc(fmtlen);

    // RBF - Update manpage and help message with 'd' for splitformat
    if ('d' == fmt[0])
      snprintf(retval,fmtlen+1,"%0*d",fmtlen,num+1);
    else
    {
      /* Fill the retval in reverse while constantly dividing num apropriately */
      for (i = fmtlen - 1; i >= 0; i--) {
        int x;
	
        if (fmt[i] == 'a') {
	  x = num % NUM_LETTERS;
	  retval[i] = letters[x];
	  num = num / NUM_LETTERS;
        } else {
	  x = num % NUM_NUMBERS;
	  retval[i] = numbers[x];
	  num = num / NUM_NUMBERS;
        }
      }
      retval[fmtlen] = '\0';
    }
    
    return retval;
}

/* Given a format string, determine the maximum number of splits
 * that can be used. */
static int maxsplits(char *fmt)
{
    int fmtlen = strlen(fmt);
    int i;
    int retval = 1;

    assert(fmtlen > 0);
    
    for (i = fmtlen - 1; i >= 0; i--)
        retval *= fmt[i] == 'a' ? NUM_LETTERS : NUM_NUMBERS;

    return retval;
}

/* Open the next extension in a split sequence */
static void open_split(split_t *split)
{
    int fd;
    int splitnum = split->total_bytes / split->max_bytes;
    mode_t perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    char *ext, *fname;
    
    ext = getext(split->format, splitnum);
    asprintf(&fname, "%s.%s", split->name, ext);
    free(ext);

    fd = open(fname, O_WRONLY | O_CREAT, perms);

    if (fd < 0)
        syscall_error(fname);

    split->currfd = fd;
    split->curr_bytes = 0;
    
    free(fname);
}

int split_write(split_t *split, const char *buf, size_t len)
{
    off_t left = split->max_bytes - split->curr_bytes;
    int nwritten = 0;

    if (left == 0 || split->currfd == -1) {
        open_split(split);
        left = split->max_bytes;
    }

    if (len <= left) {
        nwritten = full_write(split->currfd, buf, len);
        split->total_bytes += nwritten;
        split->curr_bytes += nwritten;
    } else {
        nwritten = full_write(split->currfd, buf, left);
        split->total_bytes += nwritten;
        split->curr_bytes += nwritten;
        nwritten += split_write(split, &buf[nwritten], len - nwritten);
    }

    return nwritten;
}
