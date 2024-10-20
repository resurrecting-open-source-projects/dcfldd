# configure.ac, was previously configure.in (before 2019)
#
# Copyright ?-2001    Jim Meyering <jim@meyering.net>
# Copyright 2001-2006 Nicholas Harbour <nicholasharbour@yahoo.com>
# Copyright 2019-2022 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
# Copyright 2022      David Polverari <david.polverari@gmail.com>
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

AC_INIT([dcfldd],[1.9.2],[https://github.com/resurrecting-open-source-projects/dcfldd/issues])
AC_CONFIG_SRCDIR(src/dcfldd.c)
AM_INIT_AUTOMAKE

AC_HEADER_ASSERT
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_HOST

PKG_PROG_PKG_CONFIG

AC_PROG_CC
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_EGREP

AC_USE_SYSTEM_EXTENSIONS

AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_ARG_ENABLE([runtime-endian-check],
    AC_HELP_STRING([--disable-runtime-endian-check], [disable runtime checks for endianness])
)

AC_ARG_WITH([bash-completion],
    AS_HELP_STRING([--with-bash-completion[=PATH]],
                   [Install the bash auto-completion script in this directory. @<:@default=no@:>@]),
    [],
    [with_bash_completion=no]
)

AS_IF([test "x$enable_runtime_endian_check" != "xno"], [
    dnl Do the stuff needed for enabling the feature
    AC_DEFINE([RUNTIME_ENDIAN], 1, [Define whether to check for endianness during runtime])
])

if test "x$with_bash_completion" == "xyes"; then
    PKG_CHECK_MODULES([BASH_COMPLETION], [bash-completion >= 2.0],
        [BASH_COMPLETION_DIR="`$PKG_CONFIG --variable=completionsdir bash-completion`"],
        [BASH_COMPLETION_DIR="$datadir/bash-completion/completions"])
else
    BASH_COMPLETION_DIR="$with_bash_completion"
fi

AC_CHECK_DECLS([strtol, strtoul, strtoumax, strndup])

AC_SUBST([BASH_COMPLETION_DIR])
AM_CONDITIONAL([ENABLE_BASH_COMPLETION],[test "x$with_bash_completion" != "xno"])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
