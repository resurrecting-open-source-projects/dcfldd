/* $Id: util.c,v 1.7 2005/06/15 14:33:04 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2012                        Miah Gregory <mace@debian.org>
   Copyright 2020                        David Polverari <david.polverari@gmail.com>

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

/* Return nonzero iff the file referenced by FDESC is of a type for
   which lseek's return value is known to be invalid on some systems.
   Otherwise, return zero.
   For example, return nonzero if FDESC references a character device
   (on any system) because the lseek on many Linux systems incorrectly
   returns an offset implying it succeeds for tape devices, even though
   the function fails to perform the requested operation.  In that case,
   lseek should return nonzero and set errno.  */

#include "dcfldd.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include <string.h>
#include "config.h"
#include <unistd.h>
#include <errno.h>
#include "safe-read.h"

int buggy_lseek_support(int fdesc)
{
/* We have to resort to this because on some systems, lseek doesn't work
   on some special files but doesn't return an error, either.
   In particular, the Linux tape drivers are a problem.
   For example, when I did the following using dd-4.0y or earlier on a
   Linux-2.2.17 system with an Exabyte SCSI tape drive:

   dev=/dev/nst0
   reset='mt -f $dev rewind; mt -f $dev fsf 1'
   eval $reset; dd if=$dev bs=32k of=out1
   eval $reset; dd if=$dev bs=32k of=out2 skip=1

   the resulting files, out1 and out2, would compare equal.  */

    struct stat stats;

    return (fstat(fdesc, &stats) == 0
            && (S_ISCHR(stats.st_mode)));
}

/* Throw away RECORDS blocks of BLOCKSIZE bytes on file descriptor FDESC,
   which is open with read permission for FILE.  Store up to BLOCKSIZE
   bytes of the data at a time in BUF, if necessary.  RECORDS must be
   nonzero.  */

void skip2(int fdesc, char *file, uintmax_t records, size_t blocksize,
                 unsigned char *buf)
{
    off_t offset = records * blocksize;

/* Try lseek and if an error indicates it was an inappropriate
   operation, fall back on using read.  Some broken versions of
   lseek may return zero, so count that as an error too as a valid
   zero return is not possible here.  */

    if (offset / blocksize != records
        || buggy_lseek_support(fdesc)
        || lseek(fdesc, offset, SEEK_CUR) <= 0)
    {
        while (records--) {
            ssize_t nread = safe_read(fdesc, buf, blocksize);
            if (nread < 0) {
                log_info("%s: reading %s", strerror(errno), file);
                quit(1);
            }
            /* POSIX doesn't say what to do when dd detects it has been
               asked to skip past EOF, so I assume it's non-fatal.
               FIXME: maybe give a warning.  */
            if (nread == 0)
                break;
        }
    }
}

/* This is a wrapper for lseek.  It detects and warns about a kernel
   bug that makes lseek a no-op for tape devices, even though the kernel
   lseek return value suggests that the function succeeded.

   The parameters are the same as those of the lseek function, but
   with the addition of FILENAME, the name of the file associated with
   descriptor FDESC.  The file name is used solely in the warning that's
   printed when the bug is detected.  Return the same value that lseek
   would have returned, but when the lseek bug is detected, return -1
   to indicate that lseek failed.

   The offending behavior has been confirmed with an Exabyte SCSI tape
   drive accessed via /dev/nst0 on both Linux-2.2.17 and Linux-2.4.16.  */

#ifdef __linux__

# include <error.h>
# include <sys/mtio.h>

# define MT_SAME_POSITION(P, Q) \
   ((P).mt_resid == (Q).mt_resid \
    && (P).mt_fileno == (Q).mt_fileno \
    && (P).mt_blkno == (Q).mt_blkno)

static off_t skip_via_lseek(char const *filename, int fdesc, off_t offset,
                            int whence)
{
    struct mtget s1;
    struct mtget s2;
    int got_original_tape_position = (ioctl (fdesc, MTIOCGET, &s1) == 0);
    /* known bad device type */
    /* && s.mt_type == MT_ISSCSI2 */

    off_t new_position = lseek (fdesc, offset, whence);

    if (0 <= new_position
        && got_original_tape_position
        && ioctl (fdesc, MTIOCGET, &s2) == 0
        && MT_SAME_POSITION (s1, s2))
    {
        error (0, 0, _("warning: working around lseek kernel bug for file (%s)\n\
  of mt_type=0x%0lx -- see <sys/mtio.h> for the list of types"),
               filename, s2.mt_type);
        errno = 0;
        new_position = -1;
    }

    return new_position;
}
#else
# define skip_via_lseek(Filename, Fd, Offset, Whence) lseek(Fd, Offset, Whence)
#endif

/* Throw away RECORDS blocks of BLOCKSIZE bytes on file descriptor FDESC,
   which is open with read permission for FILE.  Store up to BLOCKSIZE
   bytes of the data at a time in BUF, if necessary.  RECORDS must be
   nonzero.  If fdesc is STDIN_FILENO, advance the input offset.
   Return the number of records remaining, i.e., that were not skipped
   because EOF was reached.  */

uintmax_t skip(int fdesc, char const *file, uintmax_t records,
               size_t blocksize, char *buf)
{
    uintmax_t offset = records * blocksize;
    off_t lseekretval;
    /* Try lseek and if an error indicates it was an inappropriate operation --
       or if the the file offset is not representable as an off_t --
       fall back on using read.  */

    errno = 0;
    lseekretval = skip_via_lseek(file, fdesc, offset, SEEK_CUR);

    if (records <= OFF_T_MAX / blocksize
        && 0 <= lseekretval)
    {
        return 0;
    }
    else
    {
        int lseek_errno = errno;

        do
        {
            ssize_t nread = read(fdesc, buf, blocksize);

            if (nread < 0)
            {
                if (fdesc == STDIN_FILENO)
                {
                    log_info("%s: reading %s", strerror(errno), file);
                    if (conversions_mask & C_NOERROR)
                    {
                        print_stats();
                        continue;
                    }
                }
                else
                    log_info("%s: cannot seek %s", strerror(lseek_errno), file);
                quit(1);
            }

            if (nread == 0)
                break;
        }
        while (--records != 0);

        return records;
    }
}


void time_left(char *secstr, size_t bufsize, int seconds)
{
    int hr = seconds / (60 * 60);
    int min = seconds / 60 - hr * 60;
    int sec = seconds - (hr * 60 * 60 + min * 60);

    snprintf(secstr, bufsize, "%.02d:%.02d:%.02d remaining.", hr, min, sec);
}

/* Swap NREAD bytes in BUF, plus possibly an initial char from the
   previous call.  If NREAD is odd, save the last char for the
   next call.   Return the new start of the BUF buffer.  */

unsigned char *swab_buffer(unsigned char *buf, size_t *nread)
{
    unsigned char *bufstart = buf;
    register unsigned char *cp;
    register int i;

/* Is a char left from last time?  */
    if (char_is_saved) {
        *--bufstart = saved_char;
        (*nread)++;
        char_is_saved = 0;
    }

    if (*nread & 1) {
        /* An odd number of chars are in the buffer.  */
        saved_char = bufstart[--*nread];
        char_is_saved = 1;
    }

/* Do the byte-swapping by moving every second character two
   positions toward the end, working from the end of the buffer
   toward the beginning.  This way we only move half of the data.  */

    cp = bufstart + *nread;	/* Start one char past the last.  */
    for (i = *nread / 2; i; i--, cp -= 2)
        *cp = *(cp - 2);

    return ++bufstart;
}

/* Return the number of 1 bits in `i'. */

int bit_count(register unsigned int i)
{
    register int set_bits;

    for (set_bits = 0; i != 0; set_bits++)
        i &= i - 1;
    return set_bits;
}

/*
 * convert escape codes (i.e. "\n") in a string
 * WARNING: this modifies the data pointed to by str
 */
void replace_escapes(char *str)
{
    if (str == NULL)
        return;

    for (; *str != '\0'; str++)
        if (*str == '\\') {
            char *sptr;

            switch (*(str + 1)) {
            case 'n':
                *str++ = '\n';
                break;
            case '\\':
                *str++ = '\\';
                break;
            case 't':
                *str++ = '\t';
                break;
            case 'r':
                *str++ = '\r';
                break;
            default:
                user_error("invalid escape code \"\\%c\"", *str);
            }

            /* move all remaining chars in the string up one position */
            for (sptr = str; *sptr != '\0'; sptr++)
                *sptr = *(sptr + 1);

            replace_escapes(str + 1);
            return;
        }
}

#if (!HAVE_DECL_STRNDUP)

char *strndup(const char *str, size_t n)
{
    char *retval;
    int i;

    if (str == NULL || n == 0)
        return NULL;

    retval = malloc(n + 1);
    for (i = 0; i < n; i++)
        retval[i] = str[i];

    retval[i] = '\0';

    return retval;
}

#endif /* !HAVE_DECL_STRNDUP */

////////////////////////////////////////////////////////
// private popen2() - in-fact this is exact copy of
// newlib/libc/posix.c/popen.c with fork() instead of vfork()

static struct pid {
    struct pid *next;
        FILE *fp;
        pid_t pid;
} *pidlist;

FILE * popen2(const char *program, const char *type)
{
        struct pid *cur;
        FILE *iop;
        int pdes[2], pid;

       if ((*type != 'r' && *type != 'w')
           || (type[1]
               && (type[2] || (type[1] != 'b' && type[1] != 't'))
                               )) {
		errno = EINVAL;
		return (NULL);
	}

	if ((cur = malloc(sizeof(struct pid))) == NULL)
		return (NULL);

	if (pipe(pdes) < 0) {
		free(cur);
		return (NULL);
	}

	switch (pid = fork()) {
	case -1:			/* Error. */
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		free(cur);
		return (NULL);
		/* NOTREACHED */
	case 0:				/* Child. */
		if (*type == 'r') {
			if (pdes[1] != STDOUT_FILENO) {
				(void)dup2(pdes[1], STDOUT_FILENO);
				(void)close(pdes[1]);
			}
			(void) close(pdes[0]);
		} else {
			if (pdes[0] != STDIN_FILENO) {
				(void)dup2(pdes[0], STDIN_FILENO);
				(void)close(pdes[0]);
			}
			(void)close(pdes[1]);
		}
		execl("/bin/sh", "sh", "-c", program, NULL);
		/* On cygwin32, we may not have /bin/sh.  In that
                   case, try to find sh on PATH.  */
		execlp("sh", "sh", "-c", program, NULL);
		_exit(127);
		/* NOTREACHED */
	}

	/* Parent; assume fdopen can't fail. */
	if (*type == 'r') {
		iop = fdopen(pdes[0], type);
		(void)close(pdes[1]);
	} else {
		iop = fdopen(pdes[1], type);
		(void)close(pdes[0]);
	}

	/* Link into list of file descriptors. */
	cur->fp = iop;
	cur->pid =  pid;
	cur->next = pidlist;
	pidlist = cur;

	return (iop);
}

/*
 * pclose --
 *	Pclose returns -1 if stream is not associated with a `popened' command,
 *	if already `pclosed', or waitpid returns an error.
 */

int pclose2(FILE *iop)
{
	register struct pid *cur, *last;
	int pstat;
	pid_t pid;

	(void)fclose(iop);

	/* Find the appropriate file pointer. */
	for (last = NULL, cur = pidlist; cur; last = cur, cur = cur->next)
		if (cur->fp == iop)
			break;
	if (cur == NULL)
		return (-1);

	do {
		pid = waitpid(cur->pid, &pstat, 0);
	} while (pid == -1 && errno == EINTR);

	/* Remove the entry from the linked list. */
	if (last == NULL)
		pidlist = cur->next;
	else
		last->next = cur->next;
	free(cur);
		
	return (pid == -1 ? -1 : pstat);
}
