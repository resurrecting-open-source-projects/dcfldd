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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#include "log.h"
#include "hash.h"
#include "verify.h"

void syscall_error(char *str)
{
    syscall_error_noexit(str);
    exit(1);
}

void syscall_error_noexit(char *str)
{
    fprintf(stderr, "%s: ", program_name);
    perror(str);
    fprintf(stderr, "\n");
}

void user_error(char *str)
{
    fprintf(stderr, "%s\n", program_name, str);
}

void internal_error(char *str)
{
    fprintf(stderr, "%s: internal error: %s\n", program_name, str);
    exit(1);
}

void log_hashwindow(hashtype_t *htype, off_t wina, off_t winb, char *hash)
{
    fprintf(htype->log, "%llu - %llu: %s\n",
            (unsigned long long int) wina,
            (unsigned long long int) winb,
            hash);
}

void log_hashtotal(hashtype_t *htype, char *hash)
{
    fprintf(htype->log, "Total: %s\n", hash);
}

void log_hashalgorithm(hashtype_t *htype, char *hashname)
{
    fprintf(htype->log, "Hash Algorithm: %s\n", hashname);
}

void log_verifywindow(hashtype_t *htype, off_t wina, off_t winb, int mismatch)
{
    fprintf(htype->log, "%llu - %llu: %s\n",
            (unsigned long long int) wina,
            (unsigned long long int) winb,
            mismatch ? "Mismatch" : "Match");
}

void log_verifytotal(hashtype_t *htype, int mismatch)
{
    fprintf(htype->log, "Total: %s\n", mismatch ? "Mismatch" : "Match");
}
