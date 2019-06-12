/* $Id: output.c,v 1.4 2005/05/15 20:15:28 harbourn Exp $
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
#include "output.h"
#include "full-write.h"
#include "config.h"
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include "split.h"
#include "log.h"

outputlist_t *outputlist = NULL;

void open_output(char *filename)
{
    mode_t perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    int fd;
    int opts
        = (O_CREAT
           | (seek_records || (conversions_mask & C_NOTRUNC) ? 0 : O_TRUNC));
    
    /* Open the output file with *read* access only if we might
       need to read to satisfy a `seek=' request.  If we can't read
       the file, go ahead with write-only access; it might work.  */
    if ((! seek_records
         || (fd = open(filename, O_RDWR | opts, perms)) < 0)
        && (fd = open(filename, O_WRONLY | opts, perms)) < 0)
    {
        syscall_error(filename);
    }
#if HAVE_FTRUNCATE
    if (seek_records != 0 && !(conversions_mask & C_NOTRUNC)) {
        struct stat statbuf;
        off_t o = seek_records * output_blocksize;
        if (o / output_blocksize != seek_records)
            syscall_error(filename);
        
        if (fstat(fd, &statbuf) != 0)
            syscall_error(filename);
        
        /* Complain only when ftruncate fails on a regular file, a
           directory, or a shared memory object, as the 2000-08
           POSIX draft specifies ftruncate's behavior only for these
           file types.  For example, do not complain when Linux 2.4
           ftruncate fails on /dev/fd0.  */
        if (ftruncate(fd, o) != 0
            && (S_ISREG(statbuf.st_mode)
                || S_ISDIR(statbuf.st_mode)
                || S_TYPEISSHM(&statbuf)))
        {
            char buf[LONGEST_HUMAN_READABLE + 1];
            log_info("%s: %s: advancing past %s bytes in output file %s",
                    program_name,
                    strerror(errno),
                    human_readable(o, buf, 1, 1),
                    filename);
        }
    }
#endif /* HAVE_FTRUNCATE */
    
    outputlist_add(SINGLE_FILE, fd);
}

void open_output_pipe(char *command)
{
    FILE *stream;

    stream = popen(command, "w");
    if (stream == NULL)
        syscall_error(command);

    outputlist_add(SINGLE_FILE, fileno(stream));
}

void outputlist_add(outputtype_t type, ...)
{
    va_list ap;
    outputlist_t *ptr;
    split_t *split;
    
    va_start(ap, type);

    /* forward to the last struct in outputlist */
    for (ptr = outputlist; ptr != NULL && ptr->next != NULL; ptr = ptr->next)
        ;

    if (ptr == NULL)
        outputlist = ptr = malloc(sizeof (*ptr));
    else {
        ptr->next = malloc(sizeof (*ptr));
        ptr = ptr->next;
    }

    ptr->next = NULL;
    ptr->type = type;
    
    switch (type) {
    case SINGLE_FILE:
        ptr->data.fd = va_arg(ap, int);
        break;
    case SPLIT_FILE:
        split = malloc(sizeof *split);
        split->name = strdup(va_arg(ap, char *));
        split->format = strdup(va_arg(ap, char *));
        split->max_bytes = va_arg(ap, off_t);
        split->total_bytes = 0;
        split->curr_bytes = 0;
        split->currfd = -1;
        ptr->data.split = split;
        break;
    }

    va_end(ap);
}
    
int outputlist_write(const char *buf, size_t len)
{
    outputlist_t *ptr;
    int nwritten = 0;
    
    for (ptr = outputlist; ptr != NULL; ptr = ptr->next) {
        nwritten = 0;
        switch (ptr->type) {
        case SINGLE_FILE:
            nwritten = full_write(ptr->data.fd, buf, len);
            break;
        case SPLIT_FILE:
            nwritten = split_write(ptr->data.split, buf, len);
            break;
        }
        if (nwritten < len)
            break;
    }

    return nwritten;
}
