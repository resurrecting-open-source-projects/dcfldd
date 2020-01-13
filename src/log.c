/* $Id: log.c,v 1.6 2005/05/15 20:15:28 harbourn Exp $
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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>

#include "log.h"
#include "hash.h"
#include "verify.h"
#include <stdarg.h>
#include "hashformat.h"

FILE *errlog = NULL;

void syscall_error(char *str)
{
    syscall_error_noexit(str);
    exit(1);
}

void syscall_error_noexit(char *str)
{
    char *errstr = strerror(errno);

    fprintf(stderr, "%s:%s: %s\n", program_name, str == NULL ? "" : str, errstr);
    if (errlog != NULL)
        fprintf(errlog, "%s:%s: %s\n", program_name, str == NULL ? "" : str, errstr);
}

void user_error(char *str, ...)
{
    va_list ap;

    va_start(ap, str);
    fprintf(stderr, "%s: ", program_name);
    vfprintf(stderr, str, ap);
    fprintf(stderr, "\n");
    if (errlog != NULL) {
        fprintf(errlog, "%s: ", program_name);
        vfprintf(errlog, str, ap);
        fprintf(errlog, "\n");
    }
    va_end(ap);
    exit(1);
}

void log_info(char *str, ...)
{
    va_list ap, ap2;

    va_start(ap, str);
    va_copy(ap2, ap);
    vfprintf(stderr, str, ap);
    if (errlog != NULL) {
        vfprintf(errlog, str, ap2);
	va_end(ap2);
    }
    va_end(ap);
}

void internal_error(char *str)
{
    fprintf(stderr, "%s: internal error: %s\n", program_name, str);
    if (errlog != NULL)
        fprintf(errlog, "%s: internal error: %s\n", program_name, str);
    exit(1);
}

void log_hashwindow(hashtype_t *htype, off_t wina, off_t winb, size_t bs, char *hash)
{
    print_fmt(hashformat, htype->log, wina, winb, bs, htype->name, hash);
}

void log_hashtotal(hashtype_t *htype, off_t wina, off_t winb, size_t bs, char *hash)
{
    print_fmt(totalhashformat, htype->log, wina, winb, bs, htype->name, hash);
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
