/* full-write.c -- an interface to write that retries after interrupts
   Copyright (C) 1993, 1994, 1997, 1998, 2000 Free Software Foundation, Inc.

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
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

   Copied largely from GNU C's cccp.c.
   */

#include "dcfldd.h"

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include "safe-read.h"

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <errno.h>
#ifndef errno
extern int errno;
#endif

/* Write LEN bytes at PTR to descriptor DESC, retrying if interrupted.
   Return LEN upon success, write's (negative) error code otherwise.  */

int
full_write (int desc, const char *ptr, size_t len, int diffwr)
{
  int total_written;

  total_written = 0;
  while (len > 0)
    {
      int written = 0;
      if (diffwr) { /* Check destination block content is same as the buffer */
        char *rptr = 0;
        do {
          off_t pos = lseek(desc, 0, SEEK_CUR);
          if (pos < 0) break;
          rptr = malloc(len);
          if (!rptr) break;
          int rlen = safe_read(desc, rptr, len);
          if ((rlen <= 0) || (rlen != len) || (memcmp(rptr, ptr, len))) {
            lseek(desc, pos, SEEK_SET);
            break;
          }
          written = len;
        } while(0);
        if (rptr) free(rptr);
      }
      if (written <= 0) {
#if 0
          fprintf(stderr, "write: fd=%d, pos=%d, len=%d\n",desc, lseek(desc, 0, SEEK_CUR), len);
#endif
          written = write (desc, ptr, len);
      }
      /* write on an old Slackware Linux 1.2.13 returns zero when
	 I try to write more data than there is room on a floppy disk.
	 This puts dd into an infinite loop.  Reproduce with
	 dd if=/dev/zero of=/dev/fd0.  If you have this problem,
	 consider upgrading to a newer kernel.  */
      if (written < 0)
	{
#ifdef EINTR
	  if (errno == EINTR)
	    continue;
#endif
	  return written;
	}
      total_written += written;
      ptr += written;
      len -= written;
    }
  return total_written;
}
