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
#include "hashformat.h"
#include "log.h"
#include "util.h"
#include "sys2.h"
#include <stdio.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

format_t *hashformat = NULL;
format_t *totalhashformat = NULL;

static fmtatom_op_t fmt_string_op;
static fmtatom_op_t fmt_window_start_op;
static fmtatom_op_t fmt_window_end_op;
static fmtatom_op_t fmt_winblk_start_op;
static fmtatom_op_t fmt_winblk_end_op;
static fmtatom_op_t fmt_algorithm_op;

static fmtatom_op_t *fmtatom_op_table[] =
{ /* order must conform to fmtatom_t enum */
    fmt_string_op,
    fmt_window_start_op,
    fmt_window_end_op,
    fmt_winblk_start_op,
    fmt_winblk_end_op,
    fmt_string_op,
    fmt_algorithm_op
};

static void add_fmtatom(format_t **, fmtatom_t, void *);

static void add_fmtatom(format_t **format, fmtatom_t atom, void *data)
{
    format_t *fmt;

    if (*format == NULL) {
        *format = malloc(sizeof **format);
        fmt = *format;
    } else {
        /* cycle to the end of the list */
        for (fmt = *format; fmt->next != NULL; fmt = fmt->next)
            ;
        fmt->next = malloc(sizeof *fmt);
        fmt = fmt->next;
    }

    fmt->next = NULL;
    fmt->type = atom;
    fmt->op = fmtatom_op_table[atom];
    fmt->data = data;
}

format_t *parse_hashformat(char *str)
{
    format_t *fmt = NULL;
    int i;
    
    if (str == NULL || strlen(str) == 0)
        return NULL;

    replace_escapes(str);

    if (*str == VARIABLE_HOOK) {
        for (i = 1; str[i] != '\0' && str[i] != VARIABLE_HOOK; i++)
            ;
        if (str[i] == '\0') {
            user_error("invalid variable specifier \"%s\", variables should be terminated with another \'%c\'", str, VARIABLE_HOOK);
            exit(1);
        } else if (i == 1) {
            /* if there is two HOOKs with nothing between, remove the second and
             * push up all the following chars one position */
            for (i = 0; str[i] != '\0'; i++)
                str[i] = str[i + 1];
        } else {
            str[i] = '\0';
            str++;
            if (STREQ(str, "window_start"))
                add_fmtatom(&fmt, FMT_WINDOW_START, NULL);
            else if (STREQ(str, "window_end"))
                add_fmtatom(&fmt, FMT_WINDOW_END, NULL);
            else if (STREQ(str, "block_start"))
                add_fmtatom(&fmt, FMT_WINBLK_START, NULL);
            else if (STREQ(str, "block_end"))
                add_fmtatom(&fmt, FMT_WINBLK_END, NULL);
            else if (STREQ(str, "hash"))
                add_fmtatom(&fmt, FMT_HASH, NULL);
            else if (STREQ(str, "algorithm"))
                add_fmtatom(&fmt, FMT_ALGORITHM, NULL);
            else {
                user_error("invalid variable specifier \"%c%s%c\"",
                           VARIABLE_HOOK, str, VARIABLE_HOOK);
                exit(1);
            }
            fmt->next = parse_hashformat(&str[i]);
            return fmt;
        }
    }

    /* this loop needs to start at 1 so that "$$" will display a '$' properly */
    for (i = 1; str[i] != '\0' && str[i] != VARIABLE_HOOK; i++)
        ;

    add_fmtatom(&fmt, FMT_STRING, strndup(str, i));
    fmt->next = parse_hashformat(&str[i]);

    return fmt;
}

void print_fmt(format_t *fmt, FMTATOMOP_ARGS)
{
    for (; fmt != NULL; fmt = fmt->next)
        (fmt->op)(stream, wina, winb, blksize, alg, fmt->data == NULL ? data : fmt->data);
    fputc('\n', stream);
}

static void fmt_string_op(FMTATOMOP_ARGS)
{
    char *str = (char *)data;
    fputs(str, stream);
}

static void fmt_window_start_op(FMTATOMOP_ARGS)
{
    fprintf(stream, "%llu", (unsigned long long int) wina);
}

static void fmt_window_end_op(FMTATOMOP_ARGS)
{
    fprintf(stream, "%llu", (unsigned long long int) winb);
}

static void fmt_winblk_start_op(FMTATOMOP_ARGS)
{
    fprintf(stream, "%llu", (unsigned long long int) wina / blksize);
}

static void fmt_winblk_end_op(FMTATOMOP_ARGS)
{
    fprintf(stream, "%llu", (unsigned long long int) winb / blksize);
}

static void fmt_algorithm_op(FMTATOMOP_ARGS)
{
    fputs(alg, stream);
}
