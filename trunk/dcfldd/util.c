/* $Id: util.c,v 1.4 2005/05/14 23:20:30 harbourn Exp $
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

/* Return nonzero iff the file referenced by FDESC is of a type for
   which lseek's return value is known to be invalid on some systems.
   Otherwise, return zero.
   For example, return nonzero if FDESC references a character device
   (on any system) because the lseek on many Linux systems incorrectly
   returns an offset implying it succeeds for tape devices, even though
   the function fails to perform the requested operation.  In that case,
   lseek should return nonzero and set errno.  */

#include "dcfldd.h"
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include <string.h>
#include "config.h"

int buggy_lseek_support(int fdesc)
{
/* We have to resort to this because on some systems, lseek doesn't work
   on some special files but doesn't return an error, either.
   In particular, the Linux tape drivers are a problem.
   For example, when I did the following using dd-4.0y or earlier on a
   Linux-2.2.17 system with an Exabyte SCSI tape drive:
   
   dev=/dev/nst0
   reset='mt -f $dev rewind; mt -f $dev fsf 1'
   eval $reset; dd if=$dev bs=32k of=out1
   eval $reset; dd if=$dev bs=32k of=out2 skip=1
   
   the resulting files, out1 and out2, would compare equal.  */
    
    struct stat stats;
    
    return (fstat(fdesc, &stats) == 0
            && (S_ISCHR(stats.st_mode)));
}

/* Throw away RECORDS blocks of BLOCKSIZE bytes on file descriptor FDESC,
   which is open with read permission for FILE.  Store up to BLOCKSIZE
   bytes of the data at a time in BUF, if necessary.  RECORDS must be
   nonzero.  */

void skip(int fdesc, char *file, uintmax_t records, size_t blocksize,
                 unsigned char *buf)
{
    off_t offset = records * blocksize;
    
/* Try lseek and if an error indicates it was an inappropriate
   operation, fall back on using read.  Some broken versions of
   lseek may return zero, so count that as an error too as a valid
   zero return is not possible here.  */
    
    if (offset / blocksize != records
        || buggy_lseek_support(fdesc)
        || lseek(fdesc, offset, SEEK_CUR) <= 0)
    {
        while (records--) {
            ssize_t nread = safe_read(fdesc, buf, blocksize);
            if (nread < 0) {
                fprintf(stderr, "%s: reading %s", strerror(errno), file);
                quit(1);
            }
            /* POSIX doesn't say what to do when dd detects it has been
               asked to skip past EOF, so I assume it's non-fatal.
               FIXME: maybe give a warning.  */
            if (nread == 0)
                break;
        }
    }
}

void time_left(char *secstr, size_t bufsize, int seconds)
{
    int hr = seconds / (60 * 60);
    int min = seconds / 60 - hr * 60;
    int sec = seconds - (hr * 60 * 60 + min * 60);

    snprintf(secstr, bufsize, "%.02d:%.02d:%.02d remaining.", hr, min, sec);
}

/* Swap NREAD bytes in BUF, plus possibly an initial char from the
   previous call.  If NREAD is odd, save the last char for the
   next call.   Return the new start of the BUF buffer.  */

unsigned char *swab_buffer(unsigned char *buf, size_t *nread)
{
    unsigned char *bufstart = buf;
    register unsigned char *cp;
    register int i;
    
/* Is a char left from last time?  */
    if (char_is_saved) {
        *--bufstart = saved_char;
        (*nread)++;
        char_is_saved = 0;
    }
    
    if (*nread & 1) {
        /* An odd number of chars are in the buffer.  */
        saved_char = bufstart[--*nread];
        char_is_saved = 1;
    }
    
/* Do the byte-swapping by moving every second character two
   positions toward the end, working from the end of the buffer
   toward the beginning.  This way we only move half of the data.  */
    
    cp = bufstart + *nread;	/* Start one char past the last.  */
    for (i = *nread / 2; i; i--, cp -= 2)
        *cp = *(cp - 2);
    
    return ++bufstart;
}

/* Return the number of 1 bits in `i'. */

int bit_count(register unsigned int i)
{
    register int set_bits;

    for (set_bits = 0; i != 0; set_bits++)
        i &= i - 1;
    return set_bits;
}

/*
 * convert escape codes (i.e. "\n") in a string
 * WARNING: this modifies the data pointed to by str
 */
void replace_escapes(char *str)
{
    if (str == NULL)
        return;
    
    for (; *str != '\0'; str++)
        if (*str == '\\') {
            char *sptr;
            
            switch (*(str + 1)) {
            case 'n':
                *str++ = '\n';
                break;
            case '\\':
                *str++ = '\\';
                break;
            case 't':
                *str++ = '\t';
                break;
            case 'r':
                *str++ = '\r';
                break;
            default:
                user_error("invalid escape code \"\\%c\"", *str);
            }
            
            /* move all remaining chars in the string up one position */
            for (sptr = str; *sptr != '\0'; sptr++)
                *sptr = *(sptr + 1);

            replace_escapes(str + 1);
            return;
        } 
}   

#if (!HAVE_DECL_STRNDUP)

char *strndup(const char *str, size_t n)
{
    char *retval;
    int i;
    
    if (str == NULL || n == 0)
        return NULL;

    retval = malloc(n + 1);
    for (i = 0; i < n; i++)
        retval[i] = str[i];

    retval[i] = '\0';
    
    return retval;
}

#endif /* !HAVE_DECL_STRNDUP */
