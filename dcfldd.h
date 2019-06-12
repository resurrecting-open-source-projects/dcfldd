/* $Id: dcfldd.h,v 1.7 2005/05/19 21:00:07 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2017                        Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>

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

#ifndef DCFLDD_H
#define DCFLDD_H

#define _FILE_OFFSET_BITS 64
#define LARGEFILE_SOURCE

#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#include <sys/types.h>
#include <ctype.h>
#include <time.h>

#include <stdio.h>
#include "config.h"
#include "system.h"

#include "hash.h"

/* The official name of this program (e.g., no `g' prefix).  */
#define PROGRAM_NAME "dcfldd"

#define AUTHORS "dcfldd by Nicholas Harbour, GNU dd by Paul Rubin, David MacKenzie and Stuart Kemp"

#define SWAB_ALIGN_OFFSET 2

#ifndef SIGINFO
# define SIGINFO SIGUSR1
#endif

#ifndef S_TYPEISSHM
# define S_TYPEISSHM(Stat_ptr) 0
#endif

#define ROUND_UP_OFFSET(X, M) ((M) - 1 - (((X) + (M) - 1) % (M)))
#define PTR_ALIGN(Ptr, M) ((Ptr) \
                        + ROUND_UP_OFFSET ((char *)(Ptr) - (char *)0, (M)))

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define output_char(c)				\
do						\
    {						\
    obuf[oc++] = (c);				\
    if (oc >= output_blocksize)		\
        write_output ();			\
    }						\
while (0)

/* Default input and output blocksize. */
/* #define DEFAULT_BLOCKSIZE 512 */
#ifndef DEFAULT_BLOCKSIZE
#define DEFAULT_BLOCKSIZE 32768   /* 32k blocksize is HUGELY more efficient
                                   * for large device IO than 512 */
#endif /* DEFAULT_BLOCKSIZE */

#ifndef DEFAULT_SPLIT_FORMAT
#define DEFAULT_SPLIT_FORMAT "nnn"
#endif /* DEFAULT_SPLIT_FORMAT */

#ifndef DEFAULT_HASHWINDOW_FORMAT
#define DEFAULT_HASHWINDOW_FORMAT "#window_start# - #window_end#: #hash#"
#endif /* DEFAULT_HASHWINDOW_FORMAT */

#ifndef DEFAULT_TOTALHASH_FORMAT
#define DEFAULT_TOTALHASH_FORMAT "\nTotal (#algorithm#): #hash#"
#endif /* DEFAULT_TOTALHASH_FORMAT */

#ifndef DEFAULT_HASHCONV
#define DEFAULT_HASHCONV HASHCONV_BEFORE
#endif /* DEFAULT_HASHCONV */

/* Conversions bit masks. */
#define C_ASCII 01
#define C_EBCDIC 02
#define C_IBM 04
#define C_BLOCK 010
#define C_UNBLOCK 020
#define C_LCASE 040
#define C_UCASE 0100
#define C_SWAB 0200
#define C_NOERROR 0400
#define C_NOTRUNC 01000
#define C_SYNC 02000
/* Use separate input and output buffers, and combine partial input blocks. */
#define C_TWOBUFS 04000

typedef enum {
    HASHCONV_BEFORE,
    HASHCONV_AFTER
} hashconv_t;

extern hashconv_t hashconv;

extern char *program_name;

extern char *input_file;
extern char *output_file;

extern size_t input_blocksize;
extern size_t output_blocksize;
extern size_t conversion_blocksize;

extern uintmax_t skip_records;
extern uintmax_t seek_records;
extern uintmax_t max_records;

extern int conversions_mask;
extern int translation_needed;

extern uintmax_t w_partial;
extern uintmax_t w_full;
extern uintmax_t r_partial;
extern uintmax_t r_full;
extern uintmax_t r_partial;
extern uintmax_t r_truncate;

extern int do_hash;
extern int do_verify;
extern int do_status;

extern int char_is_saved;
extern unsigned char saved_char;

extern time_t start_time;

extern ssize_t update_thresh;

struct conversion
{
    char *convname;
    int conversion;
};

/* FIXME: Figure out where usage() is getting called from and delete this if needed */
extern void usage(int);
extern void print_stats(void);
extern void cleanup(void);
extern inline void quit(int);

extern void parse_conversion(char *);
extern int hex2char(char *);

#endif /* DCFLDD_H */
