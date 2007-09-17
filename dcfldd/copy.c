/* $Id: copy.c,v 1.6 2005/05/19 20:59:12 harbourn Exp $
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
#include <stdlib.h>
#include <time.h>
#include "hash.h"
#include "getpagesize.h"
#include "safe-read.h"
#include "full-write.h"
#include "translate.h"
#include "sizeprobe.h"
#include "pattern.h"
#include "util.h"
#include "log.h"
#include "output.h"

static void write_output(void);
static void copy_simple(unsigned char const *, int);
static void copy_with_block(unsigned char const *, size_t);
static void copy_with_unblock(unsigned char const *, size_t);

/* Output buffer. */
unsigned char *obuf;

/* Current index into `obuf'. */
static size_t oc;

/* Index into current line, for `conv=block' and `conv=unblock'.  */
static size_t col;

/* Write, then empty, the output buffer `obuf'. */
static void write_output(void)
{
    /*int nwritten = full_write(STDOUT_FILENO, obuf, output_blocksize); */
    int nwritten = outputlist_write(obuf, output_blocksize);
    
    if (nwritten != output_blocksize) {
        if (nwritten > 0)
            w_partial++;
        quit(1);
    }
    else
        w_full++;
    oc = 0;
}

/* Copy NREAD bytes of BUF, with no conversions.  */

static void copy_simple(unsigned char const *buf, int nread)
{
    int nfree;			/* Number of unused bytes in `obuf'.  */
    const unsigned char *start = buf; /* First uncopied char in BUF.  */
    
    do {
        nfree = output_blocksize - oc;
        if (nfree > nread)
            nfree = nread;
        
        memcpy((char *) (obuf + oc), (char *) start, nfree);
        
        nread -= nfree;		/* Update the number of bytes left to copy. */
        start += nfree;
        oc += nfree;
        if (oc >= output_blocksize)
            write_output();
    } while (nread > 0);
}

/* Copy NREAD bytes of BUF, doing conv=block
   (pad newline-terminated records to `conversion_blocksize',
   replacing the newline with trailing spaces).  */

static void copy_with_block(unsigned char const *buf, size_t nread)
{
    size_t i;
    
    for (i = nread; i; i--, buf++) {
        if (*buf == newline_character) {
            if (col < conversion_blocksize) {
                size_t j;
                for (j = col; j < conversion_blocksize; j++)
                    output_char(space_character);
            }
            col = 0;
        } else {
            if (col == conversion_blocksize)
                r_truncate++;
            else if (col < conversion_blocksize)
                output_char(*buf);
            col++;
        }
    }
}

/* Copy NREAD bytes of BUF, doing conv=unblock
   (replace trailing spaces in `conversion_blocksize'-sized records
   with a newline).  */
static void copy_with_unblock(unsigned char const *buf, size_t nread)
{
    size_t i;
    unsigned char c;
    static int pending_spaces = 0;
    
    for (i = 0; i < nread; i++) {
        c = buf[i];
        
        if (col++ >= conversion_blocksize) {
            col = pending_spaces = 0; /* Wipe out any pending spaces.  */
            i--;			/* Push the char back; get it later. */
            output_char(newline_character);
        } else if (c == space_character)
            pending_spaces++;
        else {
            /* `c' is the character after a run of spaces that were not
               at the end of the conversion buffer.  Output them.  */
            while (pending_spaces) {
                output_char(space_character);
                --pending_spaces;
            }
            output_char(c);
        }
    }
}

/* The main loop.  */

int dd_copy(void)
{
    unsigned char *ibuf, *bufstart; /* Input buffer. */
    unsigned char *real_buf;	  /* real buffer address before alignment */
    unsigned char *real_obuf;
    ssize_t nread;		/* Bytes read in the current block. */
    int exit_status = 0;
    int input_from_stream = !!input_file;
    int input_from_pattern = !input_from_stream;
    size_t page_size = getpagesize();
    size_t n_bytes_read;    
    
    /* Leave at least one extra byte at the beginning and end of `ibuf'
       for conv=swab, but keep the buffer address even.  But some peculiar
       device drivers work only with word-aligned buffers, so leave an
       extra two bytes.  */
    
    /* Some devices require alignment on a sector or page boundary
       (e.g. character disk devices).  Align the input buffer to a
       page boundary to cover all bases.  Note that due to the swab
       algorithm, we must have at least one byte in the page before
       the input buffer;  thus we allocate 2 pages of slop in the
       real buffer.  8k above the blocksize shouldn't bother anyone.
    
       The page alignment is necessary on any linux system that supports
       either the SGI raw I/O patch or Steven Tweedies raw I/O patch.
       It is necessary when accessing raw (i.e. character special) disk
       devices on Unixware or other SVR4-derived system.  */
    
    real_buf = (unsigned char *) malloc(input_blocksize
                                        + 2 * SWAB_ALIGN_OFFSET
                                        + 2 * page_size - 1);
    ibuf = real_buf;
    ibuf += SWAB_ALIGN_OFFSET;	/* allow space for swab */
    
    ibuf = PTR_ALIGN(ibuf, page_size);

    /* Init */
    if (do_hash) 
        hash_update(ihashlist, NULL, 0);
    
    if (conversions_mask & C_TWOBUFS) {
        /* Page-align the output buffer, too.  */
        real_obuf = (unsigned char *) malloc(output_blocksize + page_size - 1);
        obuf = PTR_ALIGN(real_obuf, page_size);
    } else {
        real_obuf = NULL;
        obuf = ibuf;
    }
    
    if (!input_from_pattern)
        if (skip_records != 0)
            skip(STDIN_FILENO, input_file, skip_records, input_blocksize, ibuf);
    
    if (seek_records != 0) {
        outputlist_t *listptr;

        for (listptr = outputlist; listptr != NULL; listptr = listptr->next) {
            skip(listptr->data.fd, "", seek_records, output_blocksize, obuf);
        }
    }
    
    if (max_records == 0)
        quit(exit_status);
    
    if (input_from_pattern) {
        replicate_pattern(pattern, ibuf, input_blocksize);
        nread = n_bytes_read = input_blocksize;
    }
    
    while (1) {
        /* Display an update message */
        if (do_status && w_full % update_thresh == 0 && w_full != 0) {
            off_t total_bytes = w_full * input_blocksize;
            off_t total_mb = total_bytes / 1048576;
    
            if (probe == PROBE_NONE || probed_size == 0)
                fprintf(stderr, "\r%llu blocks (%lluMb) written.", 
                        w_full, total_mb);
            else {
                time_t curr_time = time(NULL);
                int seconds = (int)difftime(curr_time, start_time);
                off_t probed_mb = probed_size / 1048576;
                float fprcnt = total_bytes / (float)probed_size;
                float fprcnt_remaining = 1.0 - fprcnt;
                int prcnt = (int)(fprcnt * 100);
                int seconds_remaining = (int)(seconds *
                                              (fprcnt_remaining / fprcnt));
                char secstr[100];
    
                time_left(secstr, sizeof secstr, seconds_remaining);
                fprintf(stderr, "\r[%d%% of %lluMb] %llu blocks (%lluMb) written. %s",
                        prcnt, probed_mb, w_full, total_mb, secstr);
            }	
        }
    
        if (r_partial + r_full >= max_records)
            break;
    
        /* Zero the buffer before reading, so that if we get a read error,
           whatever data we are able to read is followed by zeros.
           This minimizes data loss. */
        if (!input_from_pattern) {
            if ((conversions_mask & C_SYNC) && (conversions_mask & C_NOERROR))
                memset((char *) ibuf,
                       (conversions_mask & (C_BLOCK | C_UNBLOCK)) ? ' ' : '\0',
                       input_blocksize);
    
            nread = safe_read(STDIN_FILENO, ibuf, input_blocksize);
        }
        
        if (nread == 0)
            break;			/* EOF.  */
    
        if (nread < 0 && !input_from_pattern) {
            syscall_error_noexit(input_file);
            if (conversions_mask & C_NOERROR)
            {
                print_stats();
                /* Seek past the bad block if possible. */
                lseek(STDIN_FILENO, (off_t) input_blocksize, SEEK_CUR);
                if (conversions_mask & C_SYNC) {
                    /* Replace the missing input with null bytes and
                       proceed normally.  */
                    // EXPERIMENTAL: let's try re-zeroing this buffer
                    memset((char *) ibuf,
                           (conversions_mask & (C_BLOCK | C_UNBLOCK)) ? ' ' : '\0',
                           input_blocksize);
                    nread = 0;
                } else
                    continue;
            } else {
                /* Write any partial block. */
                exit_status = 2;
                break;
            }
        }
        n_bytes_read = nread;
    
        if (do_hash && hashconv == HASHCONV_BEFORE)
            hash_update(ihashlist, ibuf, n_bytes_read);
        
        if (n_bytes_read < input_blocksize) {
            r_partial++;
            if (conversions_mask & C_SYNC) {
                if (!(conversions_mask & C_NOERROR))
                    /* If C_NOERROR, we zeroed the block before reading. */
                    memset((char *) (ibuf + n_bytes_read),
                           (conversions_mask & (C_BLOCK | C_UNBLOCK)) ? ' ' : '\0',
                           input_blocksize - n_bytes_read);
		/* nread is only zero when an error has occured
		   In that case we need to pad this block with zeros.
		   Otherwise, we'll just write out whatever we have */
		if (0 == nread)
		  n_bytes_read = input_blocksize;
            }
        }
        else
            r_full++;
        
        if (ibuf == obuf) {		/* If not C_TWOBUFS. */
            /* int nwritten = full_write(STDOUT_FILENO, obuf, n_bytes_read); */
            int nwritten = outputlist_write(obuf, n_bytes_read);
            
            if (nwritten < 0) 
                syscall_error(output_file);
            else if (n_bytes_read == input_blocksize)
                w_full++;
            else
                w_partial++;
        } else {  /* If C_TWOBUFS */
            /* Do any translations on the whole buffer at once.  */
    
            if (translation_needed)
                translate_buffer(ibuf, n_bytes_read);
    
            if (conversions_mask & C_SWAB)
                bufstart = swab_buffer(ibuf, &n_bytes_read);
            else
                bufstart = ibuf;
            
            if (conversions_mask & C_BLOCK)
                copy_with_block(bufstart, n_bytes_read);
            else if (conversions_mask & C_UNBLOCK)
                copy_with_unblock(bufstart, n_bytes_read);
            else
                copy_simple(bufstart, n_bytes_read);
        }
        
        if (do_hash && hashconv == HASHCONV_AFTER)
            hash_update(ihashlist, ibuf, n_bytes_read);
    }

    
    /* If we have a char left as a result of conv=swab, output it.  */
    if (char_is_saved) {
        if (conversions_mask & C_BLOCK)
            copy_with_block(&saved_char, 1);
        else if (conversions_mask & C_UNBLOCK)
            copy_with_unblock(&saved_char, 1);
        else
            output_char(saved_char);
    }
    
    if ((conversions_mask & C_BLOCK) && col > 0) {
        /* If the final input line didn't end with a '\n', pad
           the output block to `conversion_blocksize' chars.  */
        unsigned int i;
        for (i = col; i < conversion_blocksize; i++)
            output_char(space_character);
    }
    
    if ((conversions_mask & C_UNBLOCK) && col == conversion_blocksize)
        /* Add a final '\n' if there are exactly `conversion_blocksize'
           characters in the final record. */
        output_char(newline_character);
    
    /* Write out the last block. */
    if (oc != 0) {
        /* int nwritten = full_write(STDOUT_FILENO, obuf, oc); */
        int nwritten = outputlist_write(obuf, oc);
        
        if (nwritten > 0)
            w_partial++;
        if (nwritten < 0) {
            syscall_error(output_file);
        }
    }
    
    free(real_buf);
    if (real_obuf)
        free(real_obuf);
    
    if (do_hash) {
        hash_remainder(ihashlist, WINDOW_CTX);
        display_totalhash(ihashlist, TOTAL_CTX);
    }
        
    return exit_status;
}
