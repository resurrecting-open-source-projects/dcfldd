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