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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include "config.h"
#include "system.h"
#include "sizeprobe.h"

static off_t midpoint(off_t a, off_t b, long blksize);
static off_t get_dev_size(int, long);

/* Which file (if any) to probe the size of */
int probe = PROBE_NONE; 
off_t probed_size;

/*
 * Compute a block-resolution midpoint (c) of a and b
 */
static off_t midpoint(off_t a, off_t b, long blksize)
{
    off_t aprime = a / blksize;
    off_t bprime = b / blksize;
    off_t c, cprime;

    cprime = (bprime - aprime) / 2 + aprime;
    c = cprime * blksize;

    return c;
}

#if defined (__linux__)

#include <sys/ioctl.h>
#include <sys/mount.h>

/* I stole this from Jesse Kornblum's md5deep */
static off_t get_dev_size(int fd, long blksize) 
{
    off_t num_sectors = 0;
  
    if (ioctl(fd, BLKGETSIZE, &num_sectors))
        fprintf(stderr,"%s: ioctl call to BLKGETSIZE failed.\n", program_name);
    else 
        return (num_sectors * 512);
}

#elif defined (__MacOSX__)

#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <machine/endian.h>

/* I also stole this from Jesse Kornblum's md5deep */
static static off_t get_dev_size(int fd, long blksize)
{
    FILE *f = fdopen(fd, "r");
    off_t total = 0;
    off_t original = ftello(f);
    int ok = TRUE;

    if (S_ISBLK(info.st_mode)) {
        daddr_t blocksize = 0;
        daddr_t blockcount = 0;


    /* Get the block size */
        if (ioctl(fd, DKIOCGETBLOCKSIZE,blocksize) < 0) {
            ok = FALSE;
#if defined(__DEBUG)
            perror("DKIOCGETBLOCKSIZE failed");
#endif
        } 
  
        /* Get the number of blocks */
        if (ok) {
            if (ioctl(fd, DKIOCGETBLOCKCOUNT, blockcount) < 0) {
#if defined(__DEBUG)
                perror("DKIOCGETBLOCKCOUNT failed");
#endif
            }
        }
        
        total = blocksize * blockcount;
        
    } else {
        
        /* I don't know why, but if you don't initialize this value you'll
           get wildly innacurate results when you try to run this function */
        
        if ((fseeko(f,0,SEEK_END)))
            return 0;
        total = ftello(f);
        if ((fseeko(f,original,SEEK_SET)))
            return 0;
    }
    
    return (total - original);
}

#else /* all other *nix */
/*
 * Guess the size of a device file.
 * Note: this is only used to give time estimates.
 *       Even if this is way off or broken,
 *       the forensic validity of the tool remains.
 **************************************************
 * This algorithm works by reading a block starting
 * at offset 0 then 1, 2, 4, 8, 16, etc and doubles
 * until it reaches a point where it fails, then it
 * iteratively backtracks by half the distance to 
 * the last known good read. It goes back and forth
 * until it knows the last readable block on the
 * device. Theoretically, this should give EXACTLY
 * the size of the device considering that the
 * seeks and reads work.  this algorithm will
 * obviously wreak havok if you try it against a
 * tape device, you have been warned.
 */
static off_t get_dev_size(int fd, long blksize)
{   /* this function is awesome */
    off_t curr = 0, amount = 0; 
    void *buf;
    off_t told;

    if (blksize == 0)
        return 0;

    buf = malloc(blksize);

    for (;;) {
        ssize_t nread;

        lseek(fd, curr, SEEK_SET);
        nread = read(fd, buf, blksize);
        if (nread < blksize) {
            if (nread <= 0) {
                if (curr == amount) {
                    free(buf);
                    lseek(fd, 0, SEEK_SET);
                    return amount;
                }
                curr = midpoint(amount, curr, blksize);
            } else { /* 0 < nread < blksize */
                free(buf);
                lseek(fd, 0, SEEK_SET);
                return amount + nread;
            }
        } else {
            amount = curr + blksize;
            curr = amount * 2;
        }
    }
    free(buf);
    lseek(fd, 0, SEEK_SET);
    return amount;
}

#endif /* if defined (__linux__), etc.. */

void sizeprobe(int fd)
{
    struct stat statbuf;

    if (fstat(fd, &statbuf) == -1) {
        fprintf(stderr, "%s: stating file", strerror(errno));
        return;
    }

    if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode))
        probed_size = statbuf.st_size;
    else if (S_ISCHR(statbuf.st_mode) || S_ISBLK(statbuf.st_mode))
        probed_size = get_dev_size(fd, statbuf.st_blksize);
}
