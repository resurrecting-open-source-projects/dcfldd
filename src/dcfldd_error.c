/*
 * dcfldd_error.c -- replacement for non-portable GNU libc's error()
 * Copyright (C) 2024 David da Silva Polverari
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// dcfldd defines program_name and sets it to argv[0]
extern char *program_name;

/*
 * dcfldd_error(): a replacement for glibc's error() for usage within dcfldd
 *
 * WARNING: this function is not intended as a full drop-in replacement for
 * error(). One example difference is that glibc's error function reads the
 * program name from a global variable "program_invocation_name" (see "man 3
 * program_invocation_name") whereas the implementation here is using dcfldd's
 * own global variable "program_name", instead.
 */

void
dcfldd_error(int status, int errnum, const char *format, ...)
{
	assert(program_name != NULL);
	va_list args;
	va_start(args, format);

	fflush (stdout);
	fprintf(stderr, "%s: ", program_name);

	vfprintf(stderr, format, args);
	va_end(args);

	if (errnum) {
		fprintf(stderr, ": %s", strerror(errnum));
	}

	fprintf(stderr, "\n");

	if (status) {
		exit(status);
	}
}
