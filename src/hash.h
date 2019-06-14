/* $Id: hash.h,v 1.4 2005/05/14 23:20:30 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2012                        Miah Gregory <mace@debian.org>
   
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

#ifndef HASH_H
#define HASH_H

#include "dcfldd.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"

#include <sys/types.h>
#include <stdio.h>

/* bytes_in_window and bytes_in_total are only used for dd_copy() */
extern off_t bytes_in_window;  
extern off_t bytes_in_total;

extern void (*hashinit)(void *);
extern void (*hashupdate)(void *, const void *, size_t);
extern void (*hashfinal)(void *, void *);

extern void *hashstr_buf;
extern size_t hashstr_buf_size;

typedef uint32_t hashflag_t;

extern hashflag_t hashflags;

typedef struct hashtype
{
    char *name;
    hashflag_t flag;
    void *window_context;
    void *total_context;
    void *vwindow_context;
    void *vtotal_context;
    void (*init)(void *);
    void (*update)(void *, const void *, size_t);
    void (*final)(void *, void *);
    void *hashstr_buf;
    size_t hashstr_buf_size;
    FILE *log;
} hashtype_t;

typedef struct hashlist_s
{
    struct hashlist_s *next;
    hashtype_t *hash;
} hashlist_t;

extern hashlist_t *ihashlist;

extern struct hashtype hashops[];

extern FILE *hash_log;

/* this enum order must correspond to their position in the hashops[] array */
enum {MD5 = 0, SHA1, SHA256, SHA384, SHA512};

enum {WINDOW_CTX, TOTAL_CTX, VWINDOW_CTX, VTOTAL_CTX};

#ifndef VERIFY_HASH
#define VERIFY_HASH MD5
#endif

#ifndef DEFAULT_HASH
#define DEFAULT_HASH MD5
#endif

extern off_t bytes_in_window;
extern off_t bytes_in_total;
extern off_t hash_windowlen;
extern off_t window_beginning;

extern void display_windowhash(hashlist_t *, off_t);
extern void display_totalhash(hashlist_t *, int);
extern void hash_update(hashlist_t *, void *, size_t);
extern void hash_update_buf(hashlist_t *, int, int, void *, size_t);
extern void hash_remainder(hashlist_t *, int);

extern void init_hashlist(hashlist_t **hashlist, hashflag_t flags);

/* inner hashl_* funcitons are for iterating over hashlists */
extern void hashl_init(hashlist_t *, int);
extern void hashl_update(hashlist_t *, int, const void *, size_t);
extern void hashl_final(hashlist_t *, int);

#endif /* HASH_H */
