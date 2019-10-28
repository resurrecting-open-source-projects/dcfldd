/* $Id: verify.c,v 1.3 2005/05/13 18:52:06 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2015                        Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
   Copyright 2019                        Bernhard Übelacker <bernhardu@mailbox.org>

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

#include "dcfldd.h"
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include "config.h"
#include "hash.h"
#include "getpagesize.h"
#include "safe-read.h"
#include "sizeprobe.h"
#include "pattern.h"
#include "util.h"
#include "log.h"

static int verify_update(hashlist_t *, void *, void *, size_t, size_t);
static void verify_remainder(hashlist_t *);

/* The name of the verify file, or NULL if none.
 * Verify file is used as a secondary input file and the input
 * file is compared against it via the use of their hashes. */
char *verify_file = NULL;
int verify_fd;
FILE *verify_log;

/* Skip this many records of `input_blocksize' bytes before reading */
uintmax_t vskip_records = 0;

static int verify_update(hashlist_t *hashl,
                         void *ibuf, void *vbuf,
                         size_t ilen, size_t vlen)
{
    size_t left_in_window = hash_windowlen - (bytes_in_window);
    int cmp = 0;

    if (bytes_in_total == 0) {
        hashl_init(hashl, TOTAL_CTX);
        hashl_init(hashl, VTOTAL_CTX);
    }

    if (hash_windowlen == 0) {
        hash_update_buf(hashl, WINDOW_CTX, TOTAL_CTX, ibuf, ilen);
        hash_update_buf(hashl, VWINDOW_CTX, VTOTAL_CTX, vbuf, vlen);
    } else {
        if (bytes_in_window == 0) {
            hashl_init(hashl, WINDOW_CTX);
            hashl_init(hashl, VWINDOW_CTX);
        }

        if (ilen >= left_in_window || vlen >= left_in_window) {
            char *ihash, *vhash;

            hash_update_buf(hashl, WINDOW_CTX, TOTAL_CTX,
                            ibuf, min(ilen, left_in_window));
            hash_update_buf(hashl, VWINDOW_CTX, VTOTAL_CTX,
                            vbuf, min(vlen, left_in_window));

            /* if verify ever wants to do more than one hash, change this */
            hashl_final(hashl, WINDOW_CTX);
            ihash = strdup(hashl->hash->hashstr_buf);
            hashl_final(hashl, VWINDOW_CTX);
            vhash = hashl->hash->hashstr_buf;

            cmp = memcmp(ihash, vhash, hashl->hash->hashstr_buf_size);
            free(ihash);

            if (cmp != 0)
            {
                log_verifywindow(hashl->hash, window_beginning,
                                 (window_beginning + hash_windowlen), cmp);
                return 1;
            }

            window_beginning += hash_windowlen;

            bytes_in_window = 0;

            verify_update(hashl, ibuf + left_in_window, vbuf + left_in_window,
                          ilen - left_in_window, vlen - left_in_window);
        } else {
            hash_update_buf(hashl, WINDOW_CTX, TOTAL_CTX, ibuf, ilen);
            hash_update_buf(hashl, VWINDOW_CTX, VTOTAL_CTX, vbuf, vlen);
        }
    }

    return 0;
}

static void verify_remainder(hashlist_t *hashl)
{
    int cmp = 0;

    if (hash_windowlen > 0 && bytes_in_window > 0) {
        char *ihash, *vhash;

        hashl_final(hashl, WINDOW_CTX);
        ihash = strdup(hashl->hash->hashstr_buf);
        hashl_final(hashl, VWINDOW_CTX);
        vhash = hashl->hash->hashstr_buf;

        cmp = memcmp(ihash, vhash, hashl->hash->hashstr_buf_size);
        free(ihash);

        if (cmp != 0)
            log_verifywindow(hashl->hash, window_beginning,
                             (window_beginning + hash_windowlen), cmp);
    }
}

/* The main loop when using the verify option. */
int dd_verify(void)
{
    unsigned char *ibuf; /* Input buffer. */
    unsigned char *vbuf; /* Verify buffer. */
    unsigned char *real_ibuf;
    unsigned char *real_vbuf;
    ssize_t i_nread;		/* Bytes read in the current input block. */
    ssize_t v_nread;        /* Bytes read in the current verify block. */
    int exit_status = 0;
    int input_from_stream = !!input_file;
    int input_from_pattern = !input_from_stream;
    size_t page_size = getpagesize();
    size_t n_bytes_read;
    char *i_hashstr_buf;
    char *v_hashstr_buf;
    size_t left_in_window;
    int mismatch = 0;
    int cmp = 0;

    real_ibuf = (unsigned char *) malloc(input_blocksize
                                         + 2 * SWAB_ALIGN_OFFSET
                                         + 2 * page_size - 1);
    ibuf = real_ibuf;
    ibuf += SWAB_ALIGN_OFFSET;	/* allow space for swab */

    ibuf = PTR_ALIGN(ibuf, page_size);

    real_vbuf = (unsigned char *) malloc(input_blocksize
                                         + 2 * SWAB_ALIGN_OFFSET
                                         + 2 * page_size - 1);
    vbuf = real_vbuf;
    vbuf += SWAB_ALIGN_OFFSET;	/* allow space for swab */

    vbuf = PTR_ALIGN(vbuf, page_size);

    i_hashstr_buf = malloc(hashstr_buf_size);
    v_hashstr_buf = malloc(hashstr_buf_size);

    if (!input_from_pattern)
        if (skip_records != 0)
            skip(STDIN_FILENO, input_file, skip_records, input_blocksize, ibuf);

    if (vskip_records != 0)
        skip(verify_fd, verify_file, vskip_records, input_blocksize, vbuf);

    if (max_records == 0)
        quit(exit_status);

    if (input_from_pattern) {
        replicate_pattern(pattern, ibuf, input_blocksize);
        i_nread = input_blocksize;
    }

    while (1)
    {
        /* Display an update message */
        if (do_status && w_full % update_thresh == 0 && w_full != 0)
        {
            off_t total_bytes = w_full * input_blocksize;
            off_t total_mb = total_bytes / 1048576;

            if (probe == PROBE_NONE || probed_size == 0)
                fprintf(stderr, "\r%llu blocks (%lluMb) written.",
                        /* [FIX] verify.c:195:25: warning: format ‘%llu’ expects argument of type ‘long long unsigned int’, but argument {3,4} has type ‘uintmax_t’ [-Wformat=] */
                        (long long unsigned int) w_full, (long long unsigned int) total_mb);
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
                fprintf(stderr,
                        "\r[%d%% of %lluMb] %llu blocks (%lluMb) written. %s",
                        /* [FIX] verify.c:210:25: warning: format ‘%llu’ expects argument of type ‘long long unsigned int’, but argument {4,5,6} has type ‘off_t’ [-Wformat=] */
                        prcnt, (long long unsigned int) probed_mb, (long long unsigned int) w_full, (long long unsigned int) total_mb, secstr);
            }
        }

        if (r_partial + r_full >= max_records)
            break;

        v_nread = safe_read(verify_fd, vbuf, input_blocksize);

        if (v_nread < 0)
            syscall_error(input_file);

        /* Zero the buffer before reading, so that if we get a read error,
           whatever data we are able to read is followed by zeros.
           This minimizes data loss. */
        if (input_from_pattern) {
            replicate_pattern(pattern, ibuf, v_nread);
            i_nread = v_nread;
        } else
            i_nread = safe_read(STDIN_FILENO, ibuf, input_blocksize);

        if (i_nread < 0 && !input_from_pattern)
            syscall_error(input_file);

        if (i_nread == 0 && v_nread == 0)
            break;

        left_in_window = hash_windowlen - bytes_in_window;
        mismatch = verify_update(ihashlist, ibuf, vbuf, i_nread, v_nread);

        if (i_nread != v_nread || (mismatch && i_nread < left_in_window)) {
            log_verifywindow(ihashlist->hash, window_beginning,
                             (window_beginning + bytes_in_window), 1);
            mismatch = 1;
        }

        if (mismatch)
            break;
    }

    free(real_ibuf);
    free(real_vbuf);

    /* verifying a remainder and total wouldnt make sense if we
     * they won't match due to different amounts read.
     */
    if (!mismatch) {
        char *ihash, *vhash;

        verify_remainder(ihashlist);

        hashl_final(ihashlist, TOTAL_CTX);
        ihash = strdup(ihashlist->hash->hashstr_buf);
        hashl_final(ihashlist, VTOTAL_CTX);
        vhash = ihashlist->hash->hashstr_buf;

        cmp = memcmp(ihash, vhash, ihashlist->hash->hashstr_buf_size);
        free(ihash);

        if (cmp != 0)
            log_verifywindow(ihashlist->hash, window_beginning,
                             (window_beginning + bytes_in_window), cmp);

        log_verifytotal(ihashlist->hash, cmp);
    } else
        log_verifytotal(ihashlist->hash, 1);

    return exit_status;
}
