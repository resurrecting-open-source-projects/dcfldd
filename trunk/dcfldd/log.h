/* $Id: log.h,v 1.4 2005/05/14 23:20:30 harbourn Exp $
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

#ifndef LOG_H
#define LOG_H

#include "dcfldd.h"
#include "hash.h"
#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>

extern FILE *errlog;

extern void syscall_error(char *);
extern void syscall_error_noexit(char *);
extern void user_error(char *, ...);
extern void internal_error(char *);
extern void log_info(char *, ...);

extern void log_hashwindow(hashtype_t *, off_t, off_t, size_t, char *);
extern void log_hashtotal(hashtype_t *, off_t, off_t, size_t, char *);

extern void log_verifywindow(hashtype_t *, off_t, off_t, int);
extern void log_verifytotal(hashtype_t *, int);

#endif /* LOG_H */
