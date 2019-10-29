# configure.ac, was previously configure.in (before 2019)
#
# Copyright ?-2001    Jim Meyering <jim@meyering.net>
# Copyright 2001-2006 Nicholas Harbour <nicholasharbour@yahoo.com>
# Copyright 2019      Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

AC_PREREQ([2.69])

AC_INIT([dcfldd], [1.5], [https://github.com/resurrecting-open-source-projects/dcfldd/issues])
AC_CONFIG_SRCDIR(src/dcfldd.c)
AM_INIT_AUTOMAKE

AM_CONFIG_HEADER(config.h)
AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AC_HEADER_STDC

AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_CHECK_DECLS([strtol, strtoul, strtoumax, strndup])

AC_OUTPUT(Makefile src/Makefile man/Makefile)
