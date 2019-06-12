/* $Id: output.c,v 1.3 2005/05/13 18:52:06 harbourn Exp $
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

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

#include "split.h"

outputlist_t *outputlist = NULL;

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
