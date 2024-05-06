/* $Id: hash.c,v 1.4 2005/05/14 23:20:30 harbourn Exp $
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
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.  */

/* GNU dd originally written by Paul Rubin, David MacKenzie, and Stuart Kemp. */

#include "dcfldd.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "hash.h"
#include "log.h"

hashflag_t hashflags = 0;

/* Md5 global data */
MD5_CTX MD5_total_context;
MD5_CTX MD5_window_context;
MD5_CTX MD5_vtotal_context;
MD5_CTX MD5_vwindow_context;
char MD5_hashstr[MD5_DIGEST_STRING_LENGTH + 1] = {'\0'};

/* SHA1 global data */
SHA1Context SHA1_total_context;
SHA1Context SHA1_window_context;
SHA1Context SHA1_vtotal_context;
SHA1Context SHA1_vwindow_context;
char SHA1_hashstr[SHA1_DIGEST_STRING_LENGTH + 1] = {'\0'};

/* SHA256 global data */
SHA256_CTX SHA256_total_context;
SHA256_CTX SHA256_window_context;
SHA256_CTX SHA256_vtotal_context;
SHA256_CTX SHA256_vwindow_context;
char SHA256_hashstr[SHA256_DIGEST_STRING_LENGTH + 1] = {'\0'};

/* SHA384 global data */
SHA384_CTX SHA384_total_context;
SHA384_CTX SHA384_window_context;
SHA384_CTX SHA384_vtotal_context;
SHA384_CTX SHA384_vwindow_context;
char SHA384_hashstr[SHA384_DIGEST_STRING_LENGTH + 1] = {'\0'};

/* SHA512 global data */
SHA512_CTX SHA512_total_context;
SHA512_CTX SHA512_window_context;
SHA512_CTX SHA512_vtotal_context;
SHA512_CTX SHA512_vwindow_context;
char SHA512_hashstr[SHA512_DIGEST_STRING_LENGTH + 1] = {'\0'};

off_t hash_windowlen = 0;
off_t window_beginning = 0;
off_t bytes_in_window = 0;
off_t bytes_in_total = 0;

void (*hashinit)(void *);
void (*hashupdate)(void *, const void *, size_t);
void (*hashfinal)(void *, void *);

void *hashstr_buf;
size_t hashstr_buf_size;

FILE *hash_log;

/* Hash algorithms */

void MD5InitGeneric(void * mdContext) {
    MD5Init((MD5_CTX *)mdContext);
}

void MD5UpdateGeneric(void * mdContext, const void * inBuf, size_t inLen) {
    assert(inLen <= (size_t)UINT_MAX);
    MD5Update((MD5_CTX *)mdContext, (const unsigned char *)inBuf, (unsigned int)inLen);
}

void MD5FinalGeneric(void * mdContext, void * buf) {
    MD5Final((MD5_CTX *)mdContext, (char *)buf);
}

void SHA1InitGeneric(void * sc) {
    SHA1Init((SHA1Context *)sc);
}

void SHA1UpdateGeneric(void * sc, const void * vdata, size_t len) {
    assert(len <= (size_t)0xFFFFFFFFu);
    SHA1Update((SHA1Context *)sc, vdata, (uint32_t)len);
}

void SHA1EndGeneric(void * sc, void * hashstrbuf) {
    SHA1End((SHA1Context *)sc, (char *)hashstrbuf);
}

void SHA256_Init_Generic(void * context) {
    SHA256_Init((SHA256_CTX *)context);
}

void SHA256_Update_Generic(void * context, const void * data, size_t len) {
    SHA256_Update((SHA256_CTX *)context, (const sha2_byte *)data, len);
}

void SHA256_End_Generic(void * context, void * buffer) {
    SHA256_End((SHA256_CTX *)context, (char *)buffer);
}

void SHA384_Init_Generic(void * context) {
    SHA384_Init((SHA384_CTX *)context);
}

void SHA384_Update_Generic(void * context, const void * data, size_t len) {
    SHA384_Update((SHA384_CTX *)context, (const sha2_byte *)data, len);
}

void SHA384_End_Generic(void * context, void * buffer) {
    SHA384_End((SHA384_CTX *)context, (char *)buffer);
}

void SHA512_Init_Generic(void * context) {
    SHA512_Init((SHA512_CTX *)context);
}

void SHA512_Update_Generic(void * context, const void * data, size_t len) {
    SHA512_Update((SHA512_CTX *)context, (const sha2_byte *)data, len);
}

void SHA512_End_Generic(void * context, void * buffer) {
    SHA512_End((SHA512_CTX *)context, (char *)buffer);
}

hashlist_t *ihashlist;

hashtype_t hashops[] =
{
    {"md5",
     1,
     &MD5_window_context,
     &MD5_total_context,
     &MD5_vwindow_context,
     &MD5_vtotal_context,
     MD5InitGeneric,
     MD5UpdateGeneric,
     MD5FinalGeneric,
     &MD5_hashstr[0],
     sizeof (MD5_hashstr),
     NULL},

    {"sha1",
     1<<1,
     &SHA1_window_context,
     &SHA1_total_context,
     &SHA1_vwindow_context,
     &SHA1_vtotal_context,
     SHA1InitGeneric,
     SHA1UpdateGeneric,
     SHA1EndGeneric,
     &SHA1_hashstr[0],
     sizeof (SHA1_hashstr),
     NULL},

    {"sha256",
     1<<2,
     &SHA256_window_context,
     &SHA256_total_context,
     &SHA256_vwindow_context,
     &SHA256_vtotal_context,
     SHA256_Init_Generic,
     SHA256_Update_Generic,
     SHA256_End_Generic,
     SHA256_hashstr,
     sizeof (SHA256_hashstr),
     NULL},

    {"sha384",
     1<<3,
     &SHA384_window_context,
     &SHA384_total_context,
     &SHA384_vwindow_context,
     &SHA384_vtotal_context,
     SHA384_Init_Generic,
     SHA384_Update_Generic,
     SHA384_End_Generic,
     &SHA384_hashstr[0],
     sizeof (SHA384_hashstr),
     NULL},

    {"sha512",
     1<<4,
     &SHA512_window_context,
     &SHA512_total_context,
     &SHA512_vwindow_context,
     &SHA512_vtotal_context,
     SHA512_Init_Generic,
     SHA512_Update_Generic,
     SHA512_End_Generic,
     &SHA512_hashstr[0],
     sizeof (SHA512_hashstr),
     NULL},

    {NULL,
     0,
     NULL,
     NULL,
     NULL,
     NULL,
     (void (*)(void *)) NULL,
     (void (*)(void *, const void *, size_t)) NULL,
     (void (*)(void *, void *)) NULL,
     NULL,
     0,
     NULL}
};

static void add_hash(hashlist_t **hashlist, int hash)
{
    hashlist_t *hlptr = *hashlist;
    int i;

    if (hlptr == NULL) {
        hlptr = malloc(sizeof (hashlist_t));
        *hashlist = hlptr;
    } else {
        for ( ; hlptr->next != NULL; hlptr = hlptr->next)
            ;
        hlptr->next = malloc(sizeof (hashlist_t));
        hlptr = hlptr->next;
    }

    hlptr->next = NULL;
    hlptr->hash = &hashops[hash];
}

/* add all the appropriate hashops according to the flags */
void init_hashlist(hashlist_t **hashlist, hashflag_t flags)
{
    int i;

    for (i = 0; hashops[i].name != NULL; i++)
        if (hashops[i].flag & flags)
            add_hash(hashlist, i);
}

/* not to be confused with init_hashlist, this function calls
 * the hashtype specific init function for each hash type in
 * the list */
void hashl_init(hashlist_t *hashlist, int context)
{
    hashlist_t *hptr;

    for (hptr = hashlist; hptr != NULL; hptr = hptr->next) {
        void *ctx;

        switch (context) {
        case WINDOW_CTX:
            ctx = hptr->hash->window_context;
            break;
        case TOTAL_CTX:
            ctx = hptr->hash->total_context;
            break;
        case VWINDOW_CTX:
            ctx = hptr->hash->vwindow_context;
            break;
        case VTOTAL_CTX:
            ctx = hptr->hash->vtotal_context;
            break;
        default:
            internal_error("unreachable branch encountered in hashl_init()");
            break;
        }

        (hptr->hash->init)(ctx);
    }
}

void hashl_update(hashlist_t *hashlist, int context, const void *buf, size_t len)
{
    hashlist_t *hptr;

    for (hptr = hashlist; hptr != NULL; hptr = hptr->next) {
        void *ctx;

        switch (context) {
        case WINDOW_CTX:
            ctx = hptr->hash->window_context;
            break;
        case TOTAL_CTX:
            ctx = hptr->hash->total_context;
            break;
        case VWINDOW_CTX:
            ctx = hptr->hash->vwindow_context;
            break;
        case VTOTAL_CTX:
            ctx = hptr->hash->vtotal_context;
            break;
        default:
            internal_error("unreachable branch encountered in hashl_update()");
            break;
        }

        (hptr->hash->update)(ctx, buf, len);
    }
}

void hashl_final(hashlist_t *hashlist, int context)
{
    hashlist_t *hptr;

    for (hptr = hashlist; hptr != NULL; hptr = hptr->next) {
        void *ctx;

        switch (context) {
        case WINDOW_CTX:
            ctx = hptr->hash->window_context;
            break;
        case TOTAL_CTX:
            ctx = hptr->hash->total_context;
            break;
        case VWINDOW_CTX:
            ctx = hptr->hash->vwindow_context;
            break;
        case VTOTAL_CTX:
            ctx = hptr->hash->vtotal_context;
            break;
        default:
            internal_error("unreachable branch encountered in hashl_final()");
            break;
        }

        /* note that this writes the hash string to the global buffer
         * for the specific hashtype, when calling this multiple times
         * (i.e. like in verify) copy that buffer out before finalizing
         * another list */
        (hptr->hash->final)(ctx, hptr->hash->hashstr_buf);
    }
}

void hash_update_buf(hashlist_t *hashlist, int winctx, int ttlctx,
                     void *buf, size_t len)
{
    if (hash_windowlen != 0) {
        hashl_update(hashlist, winctx, buf, len);
        if (winctx == WINDOW_CTX)  /* don't do this for verify or you'll get double */
            bytes_in_window += len;
    }
    hashl_update(hashlist, ttlctx, buf, len);

    if(ttlctx == TOTAL_CTX)
        bytes_in_total += len;
}

void hash_update(hashlist_t *hashlist, void *buf, size_t len)
{
    size_t left_in_window = hash_windowlen - bytes_in_window;

    if (bytes_in_total == 0)
        hashl_init(hashlist, TOTAL_CTX);

    if (hash_windowlen == 0)
        hash_update_buf(hashlist, WINDOW_CTX, TOTAL_CTX, buf, len);
    else {
        if (bytes_in_window == 0)
            hashl_init(hashlist, WINDOW_CTX);

        if (len >= left_in_window) {
            hash_update_buf(hashlist, WINDOW_CTX, TOTAL_CTX, buf, left_in_window);
            hashl_final(hashlist, WINDOW_CTX);
            display_windowhash(hashlist, hash_windowlen);
            window_beginning += hash_windowlen;
            bytes_in_window = 0;
            hash_update(hashlist, buf + left_in_window, len - left_in_window);
        } else
            hash_update_buf(hashlist, WINDOW_CTX, TOTAL_CTX, buf, len);
    }
}

void display_windowhash(hashlist_t *hashlist, off_t windowlen)
{
    hashlist_t *hptr;

    for (hptr = hashlist; hptr != NULL; hptr = hptr->next)
        log_hashwindow(hptr->hash, window_beginning, (window_beginning + windowlen),
                       input_blocksize, hptr->hash->hashstr_buf);
}

void display_totalhash(hashlist_t *hashlist, int ttlctx)
{
    hashlist_t *hptr;

    hashl_final(hashlist, ttlctx);

    for (hptr = hashlist; hptr != NULL; hptr = hptr->next)
        log_hashtotal(hptr->hash, 0, 0,
                       input_blocksize, hptr->hash->hashstr_buf);
}

void hash_remainder(hashlist_t *hashlist, int winctx)
{
    if (hash_windowlen > 0 && bytes_in_window > 0) {
        hashl_final(hashlist, winctx);
        display_windowhash(hashlist, bytes_in_window);
    }
}
