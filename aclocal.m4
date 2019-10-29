# aclocal.m4 generated automatically by aclocal 1.5

# Copyright 1996, 1997, 1998, 1999, 2000, 2001
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# Like AC_CONFIG_HEADER, but automatically create stamp file.

# serial 3

# When config.status generates a header, we must update the stamp-h file.
# This file resides in the same directory as the config header
# that is generated.  We must strip everything past the first ":",
# and everything past the last "/".

AC_PREREQ([2.12])

AC_DEFUN([AM_CONFIG_HEADER],
[ifdef([AC_FOREACH],dnl
	 [dnl init our file count if it isn't already
	 m4_ifndef([_AM_Config_Header_Index], m4_define([_AM_Config_Header_Index], [0]))
	 dnl prepare to store our destination file list for use in config.status
	 AC_FOREACH([_AM_File], [$1],
		    [m4_pushdef([_AM_Dest], m4_patsubst(_AM_File, [:.*]))
		    m4_define([_AM_Config_Header_Index], m4_incr(_AM_Config_Header_Index))
		    dnl and add it to the list of files AC keeps track of, along
		    dnl with our hook
		    AC_CONFIG_HEADERS(_AM_File,
dnl COMMANDS, [, INIT-CMDS]
[# update the timestamp
echo timestamp >"AS_ESCAPE(_AM_DIRNAME(]_AM_Dest[))/stamp-h]_AM_Config_Header_Index["
][$2]m4_ifval([$3], [, [$3]]))dnl AC_CONFIG_HEADERS
		    m4_popdef([_AM_Dest])])],dnl
[AC_CONFIG_HEADER([$1])
  AC_OUTPUT_COMMANDS(
   ifelse(patsubst([$1], [[^ ]], []),
	  [],
	  [test -z "$CONFIG_HEADERS" || echo timestamp >dnl
	   patsubst([$1], [^\([^:]*/\)?.*], [\1])stamp-h]),dnl
[am_indx=1
for am_file in $1; do
  case " \$CONFIG_HEADERS " in
  *" \$am_file "*)
    am_dir=\`echo \$am_file |sed 's%:.*%%;s%[^/]*\$%%'\`
    if test -n "\$am_dir"; then
      am_tmpdir=\`echo \$am_dir |sed 's%^\(/*\).*\$%\1%'\`
      for am_subdir in \`echo \$am_dir |sed 's%/% %'\`; do
        am_tmpdir=\$am_tmpdir\$am_subdir/
        if test ! -d \$am_tmpdir; then
          mkdir \$am_tmpdir
        fi
      done
    fi
    echo timestamp > "\$am_dir"stamp-h\$am_indx
    ;;
  esac
  am_indx=\`expr \$am_indx + 1\`
done])
])]) # AM_CONFIG_HEADER

# _AM_DIRNAME(PATH)
# -----------------
# Like AS_DIRNAME, only do it during macro expansion
AC_DEFUN([_AM_DIRNAME],
       [m4_if(m4_regexp([$1], [^.*[^/]//*[^/][^/]*/*$]), -1,
	      m4_if(m4_regexp([$1], [^//\([^/]\|$\)]), -1,
		    m4_if(m4_regexp([$1], [^/.*]), -1,
			  [.],
			  m4_patsubst([$1], [^\(/\).*], [\1])),
		    m4_patsubst([$1], [^\(//\)\([^/].*\|$\)], [\1])),
	      m4_patsubst([$1], [^\(.*[^/]\)//*[^/][^/]*/*$], [\1]))[]dnl
]) # _AM_DIRNAME

# Do all the work for Automake.  This macro actually does too much --
# some checks are only needed if your package does certain things.
# But this isn't really a big deal.

# serial 5

# There are a few dirty hacks below to avoid letting `AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...


# We require 2.13 because we rely on SHELL being computed by configure.
AC_PREREQ([2.13])

# AC_PROVIDE_IFELSE(MACRO-NAME, IF-PROVIDED, IF-NOT-PROVIDED)
# -----------------------------------------------------------
# If MACRO-NAME is provided do IF-PROVIDED, else IF-NOT-PROVIDED.
# The purpose of this macro is to provide the user with a means to
# check macros which are provided without letting her know how the
# information is coded.
# If this macro is not defined by Autoconf, define it here.
ifdef([AC_PROVIDE_IFELSE],
      [],
      [define([AC_PROVIDE_IFELSE],
              [ifdef([AC_PROVIDE_$1],
                     [$2], [$3])])])


# AM_INIT_AUTOMAKE(PACKAGE,VERSION, [NO-DEFINE])
# ----------------------------------------------
AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_REQUIRE([AC_PROG_INSTALL])dnl
# test to see if srcdir already configured
if test "`CDPATH=:; cd $srcdir && pwd`" != "`pwd`" &&
   test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run \"make distclean\" there first])
fi

# Define the identity of the package.
PACKAGE=$1
AC_SUBST(PACKAGE)dnl
VERSION=$2
AC_SUBST(VERSION)dnl
ifelse([$3],,
[AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package])])

# Autoconf 2.50 wants to disallow AM_ names.  We explicitly allow
# the ones we care about.
ifdef([m4_pattern_allow],
      [m4_pattern_allow([^AM_[A-Z]+FLAGS])])dnl

# Autoconf 2.50 always computes EXEEXT.  However we need to be
# compatible with 2.13, for now.  So we always define EXEEXT, but we
# don't compute it.
AC_SUBST(EXEEXT)
# Similar for OBJEXT -- only we only use OBJEXT if the user actually
# requests that it be used.  This is a bit dumb.
: ${OBJEXT=o}
AC_SUBST(OBJEXT)

# Some tools Automake needs.
AC_REQUIRE([AM_SANITY_CHECK])dnl
AC_REQUIRE([AC_ARG_PROGRAM])dnl
AM_MISSING_PROG(ACLOCAL, aclocal)
AM_MISSING_PROG(AUTOCONF, autoconf)
AM_MISSING_PROG(AUTOMAKE, automake)
AM_MISSING_PROG(AUTOHEADER, autoheader)
AM_MISSING_PROG(MAKEINFO, makeinfo)
AM_MISSING_PROG(AMTAR, tar)
AM_PROG_INSTALL_SH
AM_PROG_INSTALL_STRIP
# We need awk for the "check" target.  The system "awk" is bad on
# some platforms.
AC_REQUIRE([AC_PROG_AWK])dnl
AC_REQUIRE([AC_PROG_MAKE_SET])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl
AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_PROVIDE_IFELSE([AC_PROG_][CC],
                  [_AM_DEPENDENCIES(CC)],
                  [define([AC_PROG_][CC],
                          defn([AC_PROG_][CC])[_AM_DEPENDENCIES(CC)])])dnl
AC_PROVIDE_IFELSE([AC_PROG_][CXX],
                  [_AM_DEPENDENCIES(CXX)],
                  [define([AC_PROG_][CXX],
                          defn([AC_PROG_][CXX])[_AM_DEPENDENCIES(CXX)])])dnl
])

#
# Check to make sure that the build environment is sane.
#

# serial 3

# AM_SANITY_CHECK
# ---------------
AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Just in case
sleep 1
echo timestamp > conftest.file
# Do `set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   set X `ls -Lt $srcdir/configure conftest.file 2> /dev/null`
   if test "$[*]" = "X"; then
      # -L didn't work.
      set X `ls -t $srcdir/configure conftest.file`
   fi
   rm -f conftest.file
   if test "$[*]" != "X $srcdir/configure conftest.file" \
      && test "$[*]" != "X conftest.file $srcdir/configure"; then

      # If neither matched, then we have a broken ls.  This can happen
      # if, for instance, CONFIG_SHELL is bash and it inherits a
      # broken ls alias from the environment.  This has actually
      # happened.  Such a system could not be considered "sane".
      AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
alias in your environment])
   fi

   test "$[2]" = conftest.file
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
AC_MSG_RESULT(yes)])


# serial 2

# AM_MISSING_PROG(NAME, PROGRAM)
# ------------------------------
AC_DEFUN([AM_MISSING_PROG],
[AC_REQUIRE([AM_MISSING_HAS_RUN])
$1=${$1-"${am_missing_run}$2"}
AC_SUBST($1)])


# AM_MISSING_HAS_RUN
# ------------------
# Define MISSING if not defined so far and test if it supports --run.
# If it does, set am_missing_run to use it, otherwise, to nothing.
AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
test x"${MISSING+set}" = xset || MISSING="\${SHELL} $am_aux_dir/missing"
# Use eval to expand $SHELL
if eval "$MISSING --run true"; then
  am_missing_run="$MISSING --run "
else
  am_missing_run=
  am_backtick='`'
  AC_MSG_WARN([${am_backtick}missing' script is too old or missing])
fi
])

# AM_AUX_DIR_EXPAND

# For projects using AC_CONFIG_AUX_DIR([foo]), Autoconf sets
# $ac_aux_dir to `$srcdir/foo'.  In other projects, it is set to
# `$srcdir', `$srcdir/..', or `$srcdir/../..'.
#
# Of course, Automake must honor this variable whenever it calls a
# tool from the auxiliary directory.  The problem is that $srcdir (and
# therefore $ac_aux_dir as well) can be either absolute or relative,
# depending on how configure is run.  This is pretty annoying, since
# it makes $ac_aux_dir quite unusable in subdirectories: in the top
# source directory, any form will work fine, but in subdirectories a
# relative path needs to be adjusted first.
#
# $ac_aux_dir/missing
#    fails when called from a subdirectory if $ac_aux_dir is relative
# $top_srcdir/$ac_aux_dir/missing
#    fails if $ac_aux_dir is absolute,
#    fails when called from a subdirectory in a VPATH build with
#          a relative $ac_aux_dir
#
# The reason of the latter failure is that $top_srcdir and $ac_aux_dir
# are both prefixed by $srcdir.  In an in-source build this is usually
# harmless because $srcdir is `.', but things will broke when you
# start a VPATH build or use an absolute $srcdir.
#
# So we could use something similar to $top_srcdir/$ac_aux_dir/missing,
# iff we strip the leading $srcdir from $ac_aux_dir.  That would be:
#   am_aux_dir='\$(top_srcdir)/'`expr "$ac_aux_dir" : "$srcdir//*\(.*\)"`
# and then we would define $MISSING as
#   MISSING="\${SHELL} $am_aux_dir/missing"
# This will work as long as MISSING is not called from configure, because
# unfortunately $(top_srcdir) has no meaning in configure.
# However there are other variables, like CC, which are often used in
# configure, and could therefore not use this "fixed" $ac_aux_dir.
#
# Another solution, used here, is to always expand $ac_aux_dir to an
# absolute PATH.  The drawback is that using absolute paths prevent a
# configured tree to be moved without reconfiguration.

AC_DEFUN([AM_AUX_DIR_EXPAND], [
# expand $ac_aux_dir to an absolute path
am_aux_dir=`CDPATH=:; cd $ac_aux_dir && pwd`
])

# AM_PROG_INSTALL_SH
# ------------------
# Define $install_sh.
AC_DEFUN([AM_PROG_INSTALL_SH],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
install_sh=${install_sh-"$am_aux_dir/install-sh"}
AC_SUBST(install_sh)])

# One issue with vendor `install' (even GNU) is that you can't
# specify the program used to strip binaries.  This is especially
# annoying in cross-compiling environments, where the build's strip
# is unlikely to handle the host's binaries.
# Fortunately install-sh will honor a STRIPPROG variable, so we
# always use install-sh in `make install-strip', and initialize
# STRIPPROG with the value of the STRIP variable (set by the user).
AC_DEFUN([AM_PROG_INSTALL_STRIP],
[AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
INSTALL_STRIP_PROGRAM="\${SHELL} \$(install_sh) -c -s"
AC_SUBST([INSTALL_STRIP_PROGRAM])])

# serial 4						-*- Autoconf -*-



# There are a few dirty hacks below to avoid letting `AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...



# _AM_DEPENDENCIES(NAME)
# ---------------------
# See how the compiler implements dependency checking.
# NAME is "CC", "CXX" or "OBJC".
# We try a few techniques and use that to set a single cache variable.
#
# We don't AC_REQUIRE the corresponding AC_PROG_CC since the latter was
# modified to invoke _AM_DEPENDENCIES(CC); we would have a circular
# dependency, and given that the user is not expected to run this macro,
# just rely on AC_PROG_CC.
AC_DEFUN([_AM_DEPENDENCIES],
[AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_REQUIRE([AM_OUTPUT_DEPENDENCY_COMMANDS])dnl
AC_REQUIRE([AM_MAKE_INCLUDE])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl

ifelse([$1], CC,   [depcc="$CC"   am_compiler_list=],
       [$1], CXX,  [depcc="$CXX"  am_compiler_list=],
       [$1], OBJC, [depcc="$OBJC" am_compiler_list='gcc3 gcc']
       [$1], GCJ,  [depcc="$GCJ"  am_compiler_list='gcc3 gcc'],
                   [depcc="$$1"   am_compiler_list=])

AC_CACHE_CHECK([dependency style of $depcc],
               [am_cv_$1_dependencies_compiler_type],
[if test -z "$AMDEP_TRUE" && test -f "$am_depcomp"; then
  # We make a subdir and do the tests there.  Otherwise we can end up
  # making bogus files that we don't know about and never remove.  For
  # instance it was reported that on HP-UX the gcc test will end up
  # making a dummy file named `D' -- because `-MD' means `put the output
  # in D'.
  mkdir conftest.dir
  # Copy depcomp to subdir because otherwise we won't find it if we're
  # using a relative directory.
  cp "$am_depcomp" conftest.dir
  cd conftest.dir

  am_cv_$1_dependencies_compiler_type=none
  if test "$am_compiler_list" = ""; then
     am_compiler_list=`sed -n ['s/^#*\([a-zA-Z0-9]*\))$/\1/p'] < ./depcomp`
  fi
  for depmode in $am_compiler_list; do
    # We need to recreate these files for each test, as the compiler may
    # overwrite some of them when testing with obscure command lines.
    # This happens at least with the AIX C compiler.
    echo '#include "conftest.h"' > conftest.c
    echo 'int i;' > conftest.h
    echo "${am__include} ${am__quote}conftest.Po${am__quote}" > confmf

    case $depmode in
    nosideeffect)
      # after this tag, mechanisms are not by side-effect, so they'll
      # only be used when explicitly requested
      if test "x$enable_dependency_tracking" = xyes; then
	continue
      else
	break
      fi
      ;;
    none) break ;;
    esac
    # We check with `-c' and `-o' for the sake of the "dashmstdout"
    # mode.  It turns out that the SunPro C++ compiler does not properly
    # handle `-M -o', and we need to detect this.
    if depmode=$depmode \
       source=conftest.c object=conftest.o \
       depfile=conftest.Po tmpdepfile=conftest.TPo \
       $SHELL ./depcomp $depcc -c conftest.c -o conftest.o >/dev/null 2>&1 &&
       grep conftest.h conftest.Po > /dev/null 2>&1 &&
       ${MAKE-make} -s -f confmf > /dev/null 2>&1; then
      am_cv_$1_dependencies_compiler_type=$depmode
      break
    fi
  done

  cd ..
  rm -rf conftest.dir
else
  am_cv_$1_dependencies_compiler_type=none
fi
])
$1DEPMODE="depmode=$am_cv_$1_dependencies_compiler_type"
AC_SUBST([$1DEPMODE])
])


# AM_SET_DEPDIR
# -------------
# Choose a directory name for dependency files.
# This macro is AC_REQUIREd in _AM_DEPENDENCIES
AC_DEFUN([AM_SET_DEPDIR],
[rm -f .deps 2>/dev/null
mkdir .deps 2>/dev/null
if test -d .deps; then
  DEPDIR=.deps
else
  # MS-DOS does not allow filenames that begin with a dot.
  DEPDIR=_deps
fi
rmdir .deps 2>/dev/null
AC_SUBST(DEPDIR)
])


# AM_DEP_TRACK
# ------------
AC_DEFUN([AM_DEP_TRACK],
[AC_ARG_ENABLE(dependency-tracking,
[  --disable-dependency-tracking Speeds up one-time builds
  --enable-dependency-tracking  Do not reject slow dependency extractors])
if test "x$enable_dependency_tracking" != xno; then
  am_depcomp="$ac_aux_dir/depcomp"
  AMDEPBACKSLASH='\'
fi
AM_CONDITIONAL([AMDEP], [test "x$enable_dependency_tracking" != xno])
pushdef([subst], defn([AC_SUBST]))
subst(AMDEPBACKSLASH)
popdef([subst])
])

# Generate code to set up dependency tracking.
# This macro should only be invoked once -- use via AC_REQUIRE.
# Usage:
# AM_OUTPUT_DEPENDENCY_COMMANDS

#
# This code is only required when automatic dependency tracking
# is enabled.  FIXME.  This creates each `.P' file that we will
# need in order to bootstrap the dependency handling code.
AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],[
AC_OUTPUT_COMMANDS([
test x"$AMDEP_TRUE" != x"" ||
for mf in $CONFIG_FILES; do
  case "$mf" in
  Makefile) dirpart=.;;
  */Makefile) dirpart=`echo "$mf" | sed -e 's|/[^/]*$||'`;;
  *) continue;;
  esac
  grep '^DEP_FILES *= *[^ #]' < "$mf" > /dev/null || continue
  # Extract the definition of DEP_FILES from the Makefile without
  # running `make'.
  DEPDIR=`sed -n -e '/^DEPDIR = / s///p' < "$mf"`
  test -z "$DEPDIR" && continue
  # When using ansi2knr, U may be empty or an underscore; expand it
  U=`sed -n -e '/^U = / s///p' < "$mf"`
  test -d "$dirpart/$DEPDIR" || mkdir "$dirpart/$DEPDIR"
  # We invoke sed twice because it is the simplest approach to
  # changing $(DEPDIR) to its actual value in the expansion.
  for file in `sed -n -e '
    /^DEP_FILES = .*\\\\$/ {
      s/^DEP_FILES = //
      :loop
	s/\\\\$//
	p
	n
	/\\\\$/ b loop
      p
    }
    /^DEP_FILES = / s/^DEP_FILES = //p' < "$mf" | \
       sed -e 's/\$(DEPDIR)/'"$DEPDIR"'/g' -e 's/\$U/'"$U"'/g'`; do
    # Make sure the directory exists.
    test -f "$dirpart/$file" && continue
    fdir=`echo "$file" | sed -e 's|/[^/]*$||'`
    $ac_aux_dir/mkinstalldirs "$dirpart/$fdir" > /dev/null 2>&1
    # echo "creating $dirpart/$file"
    echo '# dummy' > "$dirpart/$file"
  done
done
], [AMDEP_TRUE="$AMDEP_TRUE"
ac_aux_dir="$ac_aux_dir"])])

# AM_MAKE_INCLUDE()
# -----------------
# Check to see how make treats includes.
AC_DEFUN([AM_MAKE_INCLUDE],
[am_make=${MAKE-make}
cat > confinc << 'END'
doit:
	@echo done
END
# If we don't find an include directive, just comment out the code.
AC_MSG_CHECKING([for style of include used by $am_make])
am__include='#'
am__quote=
_am_result=none
# First try GNU make style include.
echo "include confinc" > confmf
# We grep out `Entering directory' and `Leaving directory'
# messages which can occur if `w' ends up in MAKEFLAGS.
# In particular we don't look at `^make:' because GNU make might
# be invoked under some other name (usually "gmake"), in which
# case it prints its new name instead of `make'.
if test "`$am_make -s -f confmf 2> /dev/null | fgrep -v 'ing directory'`" = "done"; then
   am__include=include
   am__quote=
   _am_result=GNU
fi
# Now try BSD make style include.
if test "$am__include" = "#"; then
   echo '.include "confinc"' > confmf
   if test "`$am_make -s -f confmf 2> /dev/null`" = "done"; then
      am__include=.include
      am__quote='"'
      _am_result=BSD
   fi
fi
AC_SUBST(am__include)
AC_SUBST(am__quote)
AC_MSG_RESULT($_am_result)
rm -f confinc confmf
])

# serial 3

# AM_CONDITIONAL(NAME, SHELL-CONDITION)
# -------------------------------------
# Define a conditional.
#
# FIXME: Once using 2.50, use this:
# m4_match([$1], [^TRUE\|FALSE$], [AC_FATAL([$0: invalid condition: $1])])dnl
AC_DEFUN([AM_CONDITIONAL],
[ifelse([$1], [TRUE],
        [errprint(__file__:__line__: [$0: invalid condition: $1
])dnl
m4exit(1)])dnl
ifelse([$1], [FALSE],
       [errprint(__file__:__line__: [$0: invalid condition: $1
])dnl
m4exit(1)])dnl
AC_SUBST([$1_TRUE])
AC_SUBST([$1_FALSE])
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi])

#serial 3

dnl From Jim Meyering.
dnl Find a new-enough version of Perl.
dnl

AC_DEFUN(jm_PERL,
[
  dnl FIXME: don't hard-code 5.003
  dnl FIXME: should we cache the result?
  AC_MSG_CHECKING([for perl5.003 or newer])
  if test "${PERL+set}" = set; then
    # `PERL' is set in the user's environment.
    candidate_perl_names="$PERL"
    perl_specified=yes
  else
    candidate_perl_names='perl perl5'
    perl_specified=no
  fi

  found=no
  AC_SUBST(PERL)
  PERL="$missing_dir/missing perl"
  for perl in $candidate_perl_names; do
    # Run test in a subshell; some versions of sh will print an error if
    # an executable is not found, even if stderr is redirected.
    if ( $perl -e 'require 5.003; use File::Compare' ) > /dev/null 2>&1; then
      PERL=$perl
      found=yes
      break
    fi
  done

  AC_MSG_RESULT($found)
  test $found = no && AC_MSG_WARN([
WARNING: You don't seem to have perl5.003 or newer installed, or you lack
         a usable version of the Perl File::Compare module.  As a result,
         you may be unable to run a few tests or to regenerate certain
         files if you modify the sources from which they are derived.
] )
])

#serial 35   -*- autoconf -*-

dnl Misc type-related macros for fileutils, sh-utils, textutils.

AC_DEFUN(jm_MACROS,
[
  AC_PREREQ(2.49d)

  GNU_PACKAGE="GNU $PACKAGE"
  AC_DEFINE_UNQUOTED(GNU_PACKAGE, "$GNU_PACKAGE",
    [The concatenation of the strings `GNU ', and PACKAGE.])
  AC_SUBST(GNU_PACKAGE)

  AC_SUBST(OPTIONAL_BIN_PROGS)
  AC_SUBST(OPTIONAL_BIN_ZCRIPTS)
  AC_SUBST(MAN)
  AC_SUBST(DF_PROG)

  dnl This macro actually runs replacement code.  See isc-posix.m4.
  AC_REQUIRE([AC_ISC_POSIX])dnl

  jm_CHECK_ALL_TYPES
  jm_INCLUDED_REGEX([lib/regex.c])

  AC_REQUIRE([jm_BISON])
  AC_REQUIRE([jm_ASSERT])
  AC_REQUIRE([jm_AC_HEADER_INTTYPES_H])
  AC_REQUIRE([jm_CHECK_TYPE_STRUCT_UTIMBUF])
  AC_REQUIRE([jm_CHECK_TYPE_STRUCT_DIRENT_D_TYPE])
  AC_REQUIRE([jm_CHECK_TYPE_STRUCT_DIRENT_D_INO])
  AC_REQUIRE([jm_CHECK_DECLS])

  AC_REQUIRE([jm_PREREQ])

  AC_REQUIRE([jm_FUNC_LCHOWN])
  AC_REQUIRE([fetish_FUNC_RMDIR_NOTEMPTY])
  AC_REQUIRE([jm_FUNC_CHOWN])
  AC_REQUIRE([jm_FUNC_MKTIME])
  AC_REQUIRE([jm_FUNC_LSTAT])
  AC_REQUIRE([AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK])
  AC_REQUIRE([jm_FUNC_STAT])
  AC_REQUIRE([jm_FUNC_REALLOC])
  AC_REQUIRE([jm_FUNC_MALLOC])
  AC_REQUIRE([AC_FUNC_STRERROR_R])
  AC_REQUIRE([jm_FUNC_NANOSLEEP])
  AC_REQUIRE([jm_FUNC_READDIR])
  AC_REQUIRE([jm_FUNC_MEMCMP])
  AC_REQUIRE([jm_FUNC_GLIBC_UNLOCKED_IO])
  AC_REQUIRE([jm_FUNC_FNMATCH])
  AC_REQUIRE([jm_FUNC_GROUP_MEMBER])
  AC_REQUIRE([jm_FUNC_PUTENV])
  AC_REQUIRE([jm_AFS])
  AC_REQUIRE([jm_AC_PREREQ_XSTRTOUMAX])
  AC_REQUIRE([jm_AC_FUNC_LINK_FOLLOWS_SYMLINK])
  AC_REQUIRE([AM_FUNC_ERROR_AT_LINE])
  AC_REQUIRE([jm_FUNC_GNU_STRFTIME])
  AC_REQUIRE([jm_FUNC_MKTIME])
  AC_REQUIRE([jm_FUNC_FPENDING])

  AC_REQUIRE([jm_FUNC_GETGROUPS])
  test -n "$GETGROUPS_LIB" && LIBS="$GETGROUPS_LIB $LIBS"

  AC_REQUIRE([AC_FUNC_VPRINTF])
  AC_REQUIRE([AC_FUNC_ALLOCA])
  AC_FUNC_GETLOADAVG([lib])
  AC_REQUIRE([jm_SYS_PROC_UPTIME])
  AC_REQUIRE([jm_FUNC_FTRUNCATE])
  AC_REQUIRE([vb_FUNC_RENAME])

  AC_REPLACE_FUNCS(strcasecmp strncasecmp)
  AC_REPLACE_FUNCS(dup2)
  AC_REPLACE_FUNCS(gethostname getusershell)
  AC_REPLACE_FUNCS(stime strcspn stpcpy strstr strtol strtoul)
  AC_REPLACE_FUNCS(strpbrk)
  AC_REPLACE_FUNCS(euidaccess memcmp rmdir rpmatch strndup strverscmp)
  AC_REPLACE_FUNCS(atexit)
  AC_REPLACE_FUNCS(strnlen)
  AC_REPLACE_FUNCS(getpass)

  dnl used by e.g. intl/*domain.c and lib/canon-host.c
  AC_REPLACE_FUNCS(strdup)

  AC_REPLACE_FUNCS(memchr memcpy memmove memrchr memset)
  AC_CHECK_FUNCS(getpagesize)

  AC_REPLACE_FUNCS(mkstemp)
  if test $ac_cv_func_mkstemp != yes; then
    AC_LIBOBJ(tempname)
  fi

  # By default, argmatch should fail calling usage (1).
  AC_DEFINE(ARGMATCH_DIE, [usage (1)],
	    [Define to the function xargmatch calls on failures.])
  AC_DEFINE(ARGMATCH_DIE_DECL, [extern void usage ()],
	    [Define to the declaration of the xargmatch failure function.])

  dnl Used to define SETVBUF in sys2.h.
  dnl This evokes the following warning from autoconf:
  dnl ...: warning: AC_TRY_RUN called without default to allow cross compiling
  AC_FUNC_SETVBUF_REVERSED

  # used by sleep and shred
  # Solaris 2.5.1 needs -lposix4 to get the clock_gettime function.
  # Solaris 7 prefers the library name -lrt to the obsolescent name -lposix4.

  # Save and restore LIBS so e.g., -lrt, isn't added to it.  Otherwise, *all*
  # programs in the package would end up linked with that potentially-shared
  # library, inducing unnecessary run-time overhead.
  fetish_saved_libs=$LIBS
    AC_SEARCH_LIBS(clock_gettime, [rt posix4],
		   [LIB_CLOCK_GETTIME=$ac_cv_search_clock_gettime])
    AC_SUBST(LIB_CLOCK_GETTIME)
    AC_CHECK_FUNCS(clock_gettime)
  LIBS=$fetish_saved_libs
  AC_CHECK_FUNCS(gettimeofday)

  AC_REQUIRE([AC_FUNC_CLOSEDIR_VOID])
  AC_REQUIRE([jm_FUNC_UTIME])

  AC_CHECK_FUNCS( \
    acl \
    bcopy \
    endgrent \
    endpwent \
    fchdir \
    fdatasync \
    fseeko \
    ftime \
    ftruncate \
    getcwd \
    gethrtime \
    getmntinfo \
    hasmntopt \
    isascii \
    lchown \
    listmntent \
    localeconv \
    memcpy \
    mempcpy \
    mkfifo \
    realpath \
    resolvepath \
    sethostname \
    strchr \
    strerror \
    strrchr \
    sysinfo \
    wcrtomb \
    tzset \
  )

  AM_FUNC_GETLINE
  if test $am_cv_func_working_getline != yes; then
    AC_CHECK_FUNCS(getdelim)
  fi
  AM_FUNC_OBSTACK

  AM_FUNC_STRTOD
  AC_SUBST(POW_LIBM)
  test $am_cv_func_strtod_needs_libm = yes && POW_LIBM=-lm

  # See if linking `seq' requires -lm.
  # It does on nearly every system.  The single exception (so far) is
  # BeOS which has all the math functions in the normal runtime library
  # and doesn't have a separate math library.

  AC_SUBST(SEQ_LIBM)
  ac_seq_body='
     static double x, y;
     x = floor (x);
     x = rint (x);
     x = modf (x, &y);'
  AC_TRY_LINK([#include <math.h>], $ac_seq_body, ,
    [ac_seq_save_LIBS="$LIBS"
     LIBS="$LIBS -lm"
     AC_TRY_LINK([#include <math.h>], $ac_seq_body, SEQ_LIBM=-lm)
     LIBS="$ac_seq_save_LIBS"
    ])

  jm_LANGINFO_CODESET
  jm_GLIBC21
  jm_ICONV
  jm_FUNC_UNLINK_BUSY_TEXT

  # These tests are for df.
  jm_LIST_MOUNTED_FILESYSTEMS([list_mounted_fs=yes], [list_mounted_fs=no])
  jm_FSTYPENAME
  jm_FILE_SYSTEM_USAGE([space=yes], [space=no])
  if test $list_mounted_fs = yes && test $space = yes; then
    DF_PROG="df"
    AC_LIBOBJ(fsusage)
    AC_LIBOBJ(mountlist)
  fi
  AC_REQUIRE([jm_AC_DOS])

])

# These tests must be run before any use of AC_CHECK_TYPE,
# because that macro compiles code that tests e.g., HAVE_UNISTD_H.
# See the definition of ac_includes_default in `configure'.
AC_DEFUN(jm_CHECK_ALL_HEADERS,
[
  AC_CHECK_HEADERS( \
    errno.h  \
    fcntl.h \
    fenv.h \
    float.h \
    limits.h \
    memory.h \
    mntent.h \
    mnttab.h \
    netdb.h \
    paths.h \
    stdlib.h \
    stddef.h \
    stdint.h \
    string.h \
    sys/acl.h \
    sys/filsys.h \
    sys/fs/s5param.h \
    sys/fs_types.h \
    sys/fstyp.h \
    sys/ioctl.h \
    sys/mntent.h \
    sys/mount.h \
    sys/param.h \
    sys/resource.h \
    sys/socket.h \
    sys/statfs.h \
    sys/statvfs.h \
    sys/systeminfo.h \
    sys/time.h \
    sys/timeb.h \
    sys/vfs.h \
    sys/wait.h \
    syslog.h \
    termios.h \
    unistd.h \
    utime.h \
    values.h \
  )
])

# This macro must be invoked before any tests that run the compiler.
AC_DEFUN(jm_CHECK_ALL_TYPES,
[
  # FIXME: I shouldn't have to require this macro here.  Rather, it should
  # be required by any autoconf macro that performs a compile-time test or
  # otherwise uses confdefs.h.
  AC_REQUIRE([AC__GNU_SOURCE])

  dnl This test must come as early as possible after the compiler configuration
  dnl tests, because the choice of the file model can (in principle) affect
  dnl whether functions and headers are available, whether they work, etc.
  AC_REQUIRE([AC_SYS_LARGEFILE])

  dnl This test must precede tests of compiler characteristics like
  dnl that for the inline keyword, since it may change the degree to
  dnl which the compiler supports such features.
  AC_REQUIRE([AM_C_PROTOTYPES])

  dnl Checks for typedefs, structures, and compiler characteristics.
  AC_REQUIRE([AC_C_BIGENDIAN])
  AC_REQUIRE([AC_PROG_CC_STDC])
  AC_REQUIRE([AC_C_CONST])
  AC_REQUIRE([AC_C_VOLATILE])
  AC_REQUIRE([AC_C_INLINE])
  AC_REQUIRE([AC_C_LONG_DOUBLE])

  AC_REQUIRE([jm_CHECK_ALL_HEADERS])
  AC_REQUIRE([AC_HEADER_DIRENT])
  AC_REQUIRE([AC_HEADER_STDC])
  AC_CHECK_MEMBERS([struct stat.st_blksize],,,[$ac_includes_default
#include <sys/stat.h>
  ])
  AC_REQUIRE([AC_STRUCT_ST_BLOCKS])

  AC_REQUIRE([AC_STRUCT_TM])
  AC_REQUIRE([AC_STRUCT_TIMEZONE])
  AC_REQUIRE([AC_HEADER_STAT])
  AC_REQUIRE([AC_STRUCT_ST_MTIM_NSEC])
  AC_REQUIRE([AC_STRUCT_ST_DM_MODE])
  AC_REQUIRE([jm_CHECK_TYPE_STRUCT_TIMESPEC])

  AC_REQUIRE([AC_TYPE_GETGROUPS])
  AC_REQUIRE([AC_TYPE_MODE_T])
  AC_REQUIRE([AC_TYPE_OFF_T])
  AC_REQUIRE([AC_TYPE_PID_T])
  AC_REQUIRE([AC_TYPE_SIGNAL])
  AC_REQUIRE([AC_TYPE_SIZE_T])
  AC_REQUIRE([AC_TYPE_UID_T])
  AC_CHECK_TYPE(ino_t, unsigned long)

  dnl This relies on the fact that autoconf 2.14a's implementation of
  dnl AC_CHECK_TYPE checks includes unistd.h.
  AC_CHECK_TYPE(ssize_t, int)

  AC_REQUIRE([jm_AC_TYPE_UINTMAX_T])
  AC_REQUIRE([jm_AC_TYPE_UNSIGNED_LONG_LONG])

  AC_REQUIRE([AC_HEADER_MAJOR])
  AC_REQUIRE([AC_HEADER_DIRENT])

])

#serial 1
dnl This test replaces the one in autoconf.
dnl Currently this macro should have the same name as the autoconf macro
dnl because gettext's gettext.m4 (distributed in the automake package)
dnl still uses it.  Otherwise, the use in gettext.m4 makes autoheader
dnl give these diagnostics:
dnl   configure.in:556: AC_TRY_COMPILE was called before AC_ISC_POSIX
dnl   configure.in:556: AC_TRY_RUN was called before AC_ISC_POSIX

undefine([AC_ISC_POSIX])
AC_DEFUN(AC_ISC_POSIX,
  [
    dnl This test replaces the obsolescent AC_ISC_POSIX kludge.
    AC_CHECK_LIB(cposix, strerror, [LIBS="$LIBS -lcposix"])
  ]
)

#serial 9

dnl Initially derived from code in GNU grep.
dnl Mostly written by Jim Meyering.

dnl Usage: jm_INCLUDED_REGEX([lib/regex.c])
dnl
AC_DEFUN(jm_INCLUDED_REGEX,
  [
    dnl Even packages that don't use regex.c can use this macro.
    dnl Of course, for them it doesn't do anything.

    # Assume we'll default to using the included regex.c.
    ac_use_included_regex=yes

    # However, if the system regex support is good enough that it passes the
    # the following run test, then default to *not* using the included regex.c.
    # If cross compiling, assume the test would fail and use the included
    # regex.c.  The first failing regular expression is from `Spencer ere
    # test #75' in grep-2.3.
    AC_CACHE_CHECK([for working re_compile_pattern],
		   jm_cv_func_working_re_compile_pattern,
      AC_TRY_RUN(
[#include <stdio.h>
#include <regex.h>
	  int
	  main ()
	  {
	    static struct re_pattern_buffer regex;
	    const char *s;
	    struct re_registers regs;
	    re_set_syntax (RE_SYNTAX_POSIX_EGREP);
	    /* Add this third left square bracket, [, to balance the
	       three right ones below.  Otherwise autoconf-2.14 chokes.  */
	    s = re_compile_pattern ("a[[:]:]]b\n", 9, &regex);
	    /* This should fail with _Invalid character class name_ error.  */
	    if (!s)
	      exit (1);

	    /* This should succeed, but doesn't for e.g. glibc-2.1.3.  */
	    s = re_compile_pattern ("{1", 2, &regex);

	    if (s)
	      exit (1);

	    /* The following example is derived from a problem report
               against gawk from Jorge Stolfi <stolfi@ic.unicamp.br>.  */
	    s = re_compile_pattern ("[anù]*n", 7, &regex);
	    if (s)
	      exit (1);

	    /* This should match, but doesn't for e.g. glibc-2.2.1.  */
	    if (re_match (&regex, "an", 2, 0, &regs) != 2)
	      exit (1);

	    exit (0);
	  }
	],
	       jm_cv_func_working_re_compile_pattern=yes,
	       jm_cv_func_working_re_compile_pattern=no,
	       dnl When crosscompiling, assume it's broken.
	       jm_cv_func_working_re_compile_pattern=no))
    if test $jm_cv_func_working_re_compile_pattern = yes; then
      ac_use_included_regex=no
    fi

    test -n "$1" || AC_MSG_ERROR([missing argument])
    m4_syscmd([test -f $1])
    ifelse(m4_sysval, 0,
      [
	AC_ARG_WITH(included-regex,
	[  --without-included-regex don't compile regex; this is the default on
                          systems with version 2 of the GNU C library
                          (use with caution on other system)],
		    jm_with_regex=$withval,
		    jm_with_regex=$ac_use_included_regex)
	if test "$jm_with_regex" = yes; then
	  AC_LIBOBJ(regex)
	fi
      ],
    )
  ]
)

#serial 1

AC_DEFUN(jm_BISON,
[
  # getdate.y works with bison only.
  : ${YACC='bison -y'}
  AC_SUBST(YACC)
])

#serial 2
dnl based on code from Eleftherios Gkioulekas

AC_DEFUN(jm_ASSERT,
[
  AC_MSG_CHECKING(whether to enable assertions)
  AC_ARG_ENABLE(assert,
	[  --disable-assert        turn off assertions],
	[ AC_MSG_RESULT(no)
	  AC_DEFINE(NDEBUG,1,[Define to 1 if assertions should be disabled.]) ],
	[ AC_MSG_RESULT(yes) ]
               )
])

#serial 3

dnl From Paul Eggert.

# Define HAVE_INTTYPES_H if <inttypes.h> exists,
# doesn't clash with <sys/types.h>, and declares uintmax_t.

AC_DEFUN(jm_AC_HEADER_INTTYPES_H,
[
  AC_CACHE_CHECK([for inttypes.h], jm_ac_cv_header_inttypes_h,
  [AC_TRY_COMPILE(
    [#include <sys/types.h>
#include <inttypes.h>],
    [uintmax_t i = (uintmax_t) -1;],
    jm_ac_cv_header_inttypes_h=yes,
    jm_ac_cv_header_inttypes_h=no)])
  if test $jm_ac_cv_header_inttypes_h = yes; then
    AC_DEFINE_UNQUOTED(HAVE_INTTYPES_H, 1,
[Define if <inttypes.h> exists, doesn't clash with <sys/types.h>,
   and declares uintmax_t. ])
  fi
])

#serial 3

dnl From Jim Meyering

dnl Define HAVE_STRUCT_UTIMBUF if `struct utimbuf' is declared --
dnl usually in <utime.h>.
dnl Some systems have utime.h but don't declare the struct anywhere.

AC_DEFUN(jm_CHECK_TYPE_STRUCT_UTIMBUF,
[
  AC_CHECK_HEADERS(utime.h)
  AC_REQUIRE([AC_HEADER_TIME])
  AC_CACHE_CHECK([for struct utimbuf], fu_cv_sys_struct_utimbuf,
    [AC_TRY_COMPILE(
      [
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef HAVE_UTIME_H
# include <utime.h>
#endif
      ],
      [static struct utimbuf x; x.actime = x.modtime;],
      fu_cv_sys_struct_utimbuf=yes,
      fu_cv_sys_struct_utimbuf=no)
    ])

  if test $fu_cv_sys_struct_utimbuf = yes; then
    AC_DEFINE_UNQUOTED(HAVE_STRUCT_UTIMBUF, 1,
[Define if struct utimbuf is declared -- usually in <utime.h>.
   Some systems have utime.h but don't declare the struct anywhere. ])
  fi
])

#serial 3

dnl From Jim Meyering.
dnl
dnl Check whether struct dirent has a member named d_type.
dnl

AC_DEFUN(jm_CHECK_TYPE_STRUCT_DIRENT_D_TYPE,
  [AC_REQUIRE([AC_HEADER_DIRENT])dnl
   AC_CACHE_CHECK([for d_type member in directory struct],
		  jm_cv_struct_dirent_d_type,
     [AC_TRY_LINK(dnl
       [
#include <sys/types.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else /* not HAVE_DIRENT_H */
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */
       ],
       [struct dirent dp; dp.d_type = 0;],

       jm_cv_struct_dirent_d_type=yes,
       jm_cv_struct_dirent_d_type=no)
     ]
   )
   if test $jm_cv_struct_dirent_d_type = yes; then
     AC_DEFINE(D_TYPE_IN_DIRENT, 1,
  [Define if there is a member named d_type in the struct describing
   directory headers.])
   fi
  ]
)

#serial 3

dnl From Jim Meyering.
dnl
dnl Check whether struct dirent has a member named d_ino.
dnl

AC_DEFUN(jm_CHECK_TYPE_STRUCT_DIRENT_D_INO,
  [AC_REQUIRE([AC_HEADER_DIRENT])dnl
   AC_CACHE_CHECK([for d_ino member in directory struct],
		  jm_cv_struct_dirent_d_ino,
     [AC_TRY_LINK(dnl
       [
#include <sys/types.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else /* not HAVE_DIRENT_H */
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */
       ],
       [struct dirent dp; dp.d_ino = 0;],

       jm_cv_struct_dirent_d_ino=yes,
       jm_cv_struct_dirent_d_ino=no)
     ]
   )
   if test $jm_cv_struct_dirent_d_ino = yes; then
     AC_DEFINE(D_INO_IN_DIRENT, 1,
  [Define if there is a member named d_ino in the struct describing
   directory headers.])
   fi
  ]
)

#serial 17

dnl This is just a wrapper function to encapsulate this kludge.
dnl Putting it in a separate file like this helps share it between
dnl different packages.
AC_DEFUN(jm_CHECK_DECLS,
[
  AC_REQUIRE([_jm_DECL_HEADERS])
  AC_REQUIRE([AC_HEADER_TIME])
  headers='
#include <stdio.h>
#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#else
# if HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_UTMP_H
# include <utmp.h>
#endif

#if HAVE_GRP_H
# include <grp.h>
#endif

#if HAVE_PWD_H
# include <pwd.h>
#endif
'

  AC_CHECK_DECLS([
    free,
    getenv,
    geteuid,
    getgrgid,
    getlogin,
    getpwuid,
    getuid,
    getutent,
    lseek,
    malloc,
    memchr,
    memrchr,
    nanosleep,
    realloc,
    stpcpy,
    strndup,
    strnlen,
    strstr,
    strtoul,
    strtoull,
    ttyname], , , $headers)
])

dnl FIXME: when autoconf has support for it.
dnl This is a little helper so we can require these header checks.
AC_DEFUN(_jm_DECL_HEADERS,
[
  AC_REQUIRE([AC_HEADER_STDC])
  AC_CHECK_HEADERS(grp.h memory.h pwd.h string.h strings.h stdlib.h \
                   unistd.h sys/time.h utmp.h utmpx.h)
])

#serial 18

dnl These are the prerequisite macros for files in the lib/
dnl directories of the fileutils, sh-utils, and textutils packages.

AC_DEFUN(jm_PREREQ,
[
  jm_PREREQ_ADDEXT
  jm_PREREQ_CANON_HOST
  jm_PREREQ_DIRNAME
  jm_PREREQ_ERROR
  jm_PREREQ_GETPAGESIZE
  jm_PREREQ_HASH
  jm_PREREQ_HUMAN
  jm_PREREQ_MBSWIDTH
  jm_PREREQ_MEMCHR
  jm_PREREQ_QUOTEARG
  jm_PREREQ_READUTMP
  jm_PREREQ_REGEX
  jm_PREREQ_TEMPNAME # called by mkstemp
])

AC_DEFUN(jm_PREREQ_ADDEXT,
[
  dnl For addext.c.
  AC_SYS_LONG_FILE_NAMES
  AC_CHECK_FUNCS(pathconf)
  AC_CHECK_HEADERS(limits.h string.h unistd.h)
])

AC_DEFUN(jm_PREREQ_CANON_HOST,
[
  dnl Add any libraries as early as possible.
  dnl In particular, inet_ntoa needs -lnsl at least on Solaris5.5.1,
  dnl so we have to add -lnsl to LIBS before checking for that function.
  AC_SEARCH_LIBS(gethostbyname, [inet nsl])

  dnl These come from -lnsl on Solaris5.5.1.
  AC_CHECK_FUNCS(gethostbyname gethostbyaddr inet_ntoa)

  AC_CHECK_FUNCS(gethostbyname gethostbyaddr inet_ntoa)
  AC_CHECK_HEADERS(unistd.h string.h netdb.h sys/socket.h \
                   netinet/in.h arpa/inet.h)
])

AC_DEFUN(jm_PREREQ_DIRNAME,
[
  AC_HEADER_STDC
  AC_CHECK_HEADERS(string.h)
])

AC_DEFUN(jm_PREREQ_GETPAGESIZE,
[
  AC_CHECK_FUNCS(getpagesize)
  AC_CHECK_HEADERS(OS.h unistd.h)
])

AC_DEFUN(jm_PREREQ_HASH,
[
  AC_CHECK_HEADERS(stdlib.h stdbool.h)
  AC_REQUIRE([jm_CHECK_DECLS])
])

# If you use human.c, you need the following files:
# uintmax_t.m4 inttypes_h.m4 ulonglong.m4
AC_DEFUN(jm_PREREQ_HUMAN,
[
  AC_CHECK_HEADERS(limits.h stdlib.h string.h)
  AC_CHECK_DECLS([getenv])
  AC_REQUIRE([jm_AC_HEADER_INTTYPES_H])
  AC_REQUIRE([jm_AC_TYPE_UINTMAX_T])
])

AC_DEFUN(jm_PREREQ_MEMCHR,
[
  AC_CHECK_HEADERS(limits.h stdlib.h bp-sym.h)
])

AC_DEFUN(jm_PREREQ_QUOTEARG,
[
  AC_CHECK_FUNCS(isascii iswprint)
  jm_FUNC_MBRTOWC
  AC_CHECK_HEADERS(limits.h stddef.h stdlib.h string.h wchar.h wctype.h)
  AC_HEADER_STDC
  AC_C_BACKSLASH_A
  AC_MBSTATE_T
  AM_C_PROTOTYPES
])

AC_DEFUN(jm_PREREQ_READUTMP,
[
  AC_HEADER_STDC
  AC_CHECK_HEADERS(string.h utmp.h utmpx.h sys/param.h)
  AC_CHECK_FUNCS(utmpname)
  AC_CHECK_FUNCS(utmpxname)
  AM_C_PROTOTYPES

  if test $ac_cv_header_utmp_h = yes || test $ac_cv_header_utmpx_h = yes; then
    utmp_includes="\
$ac_includes_default
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif
"
    AC_CHECK_MEMBERS([struct utmpx.ut_user],,,[$utmp_includes])
    AC_CHECK_MEMBERS([struct utmp.ut_user],,,[$utmp_includes])
    AC_CHECK_MEMBERS([struct utmpx.ut_name],,,[$utmp_includes])
    AC_CHECK_MEMBERS([struct utmp.ut_name],,,[$utmp_includes])
    AC_LIBOBJ(readutmp)
  fi
])

AC_DEFUN(jm_PREREQ_REGEX,
[
  dnl FIXME: Maybe provide a btowc replacement someday: solaris-2.5.1 lacks it.
  dnl FIXME: Check for wctype and iswctype, and and add -lw if necessary
  dnl to get them.
  AC_CHECK_FUNCS(bzero bcopy isascii btowc)
  AC_CHECK_HEADERS(alloca.h libintl.h wctype.h wchar.h)
  AC_HEADER_STDC
  AC_FUNC_ALLOCA
])

AC_DEFUN(jm_PREREQ_TEMPNAME,
[
  AC_HEADER_STDC
  AC_HEADER_STAT
  AC_CHECK_HEADERS(fcntl.h sys/time.h stdint.h unistd.h)
  AC_CHECK_FUNCS(__secure_getenv gettimeofday)
])

#serial 2

dnl FIXME: put these prerequisite-only *.m4 files in a separate
dnl directory -- otherwise, they'll conflict with existing files.

dnl These are the prerequisite macros for GNU's error.c file.
AC_DEFUN(jm_PREREQ_ERROR,
[
  AC_CHECK_FUNCS(strerror strerror_r vprintf doprnt)
  AC_FUNC_STRERROR_R
  AC_HEADER_STDC
])

#serial 1002
# Experimental replacement for the function in the latest CVS autoconf.
# If the compile-test says strerror_r doesn't work, then resort to a
# `run'-test that works on BeOS and segfaults on DEC Unix.
# Use with the error.c file in ../lib.

undefine([AC_FUNC_STRERROR_R])

# AC_FUNC_STRERROR_R
# ------------------
AC_DEFUN([AC_FUNC_STRERROR_R],
[AC_CHECK_DECLS([strerror_r])
AC_CHECK_FUNCS([strerror_r])
if test $ac_cv_func_strerror_r = yes; then
  AC_CHECK_HEADERS(string.h)
  AC_CACHE_CHECK([for working strerror_r],
                 ac_cv_func_strerror_r_works,
   [
    AC_TRY_COMPILE(
     [
#       include <stdio.h>
#       if HAVE_STRING_H
#        include <string.h>
#       endif
     ],
     [
       char buf[100];
       char x = *strerror_r (0, buf, sizeof buf);
     ],
     ac_cv_func_strerror_r_works=yes,
     ac_cv_func_strerror_r_works=no
    )
    if test $ac_cv_func_strerror_r_works = no; then
      # strerror_r seems not to work, but now we have to choose between
      # systems that have relatively inaccessible declarations for the
      # function.  BeOS and DEC UNIX 4.0 fall in this category, but the
      # former has a strerror_r that returns char*, while the latter
      # has a strerror_r that returns `int'.
      # This test should segfault on the DEC system.
      AC_TRY_RUN(
       [
#       include <stdio.h>
#       include <string.h>
#       include <ctype.h>

	extern char *strerror_r ();

	int
	main ()
	{
	  char buf[100];
	  char x = *strerror_r (0, buf, sizeof buf);
	  exit (!isalpha (x));
	}
       ],
       ac_cv_func_strerror_r_works=yes,
       ac_cv_func_strerror_r_works=no,
       ac_cv_func_strerror_r_works=no)
    fi
  ])
  if test $ac_cv_func_strerror_r_works = yes; then
    AC_DEFINE_UNQUOTED(HAVE_WORKING_STRERROR_R, 1,
      [Define to 1 if `strerror_r' returns a string.])
  fi
fi
])# AC_FUNC_STRERROR_R

#serial 4

dnl autoconf tests required for use of mbswidth.c
dnl From Bruno Haible.

AC_DEFUN(jm_PREREQ_MBSWIDTH,
[
  AC_REQUIRE([AC_HEADER_STDC])
  AC_REQUIRE([AM_C_PROTOTYPES])
  AC_CHECK_HEADERS(limits.h stdlib.h string.h wchar.h wctype.h)
  AC_CHECK_FUNCS(isascii iswprint wcwidth)
  jm_FUNC_MBRTOWC
  headers='
#     if HAVE_WCHAR_H
#      include <wchar.h>
#     endif
'
  AC_CHECK_DECLS([wcwidth], , , $headers)
  AC_MBSTATE_T
])


# serial 1

AC_DEFUN([AM_C_PROTOTYPES],
[AC_REQUIRE([AM_PROG_CC_STDC])
AC_REQUIRE([AC_PROG_CPP])
AC_MSG_CHECKING([for function prototypes])
if test "$am_cv_prog_cc_stdc" != no; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(PROTOTYPES,1,[Define if compiler has function prototypes])
  U= ANSI2KNR=
else
  AC_MSG_RESULT(no)
  U=_ ANSI2KNR=./ansi2knr
fi
# Ensure some checks needed by ansi2knr itself.
AC_HEADER_STDC
AC_CHECK_HEADERS(string.h)
AC_SUBST(U)dnl
AC_SUBST(ANSI2KNR)dnl
])


# serial 1

# @defmac AC_PROG_CC_STDC
# @maindex PROG_CC_STDC
# @ovindex CC
# If the C compiler in not in ANSI C mode by default, try to add an option
# to output variable @code{CC} to make it so.  This macro tries various
# options that select ANSI C on some system or another.  It considers the
# compiler to be in ANSI C mode if it handles function prototypes correctly.
#
# If you use this macro, you should check after calling it whether the C
# compiler has been set to accept ANSI C; if not, the shell variable
# @code{am_cv_prog_cc_stdc} is set to @samp{no}.  If you wrote your source
# code in ANSI C, you can make an un-ANSIfied copy of it by using the
# program @code{ansi2knr}, which comes with Ghostscript.
# @end defmac

AC_DEFUN([AM_PROG_CC_STDC],
[AC_REQUIRE([AC_PROG_CC])
AC_BEFORE([$0], [AC_C_INLINE])
AC_BEFORE([$0], [AC_C_CONST])
dnl Force this before AC_PROG_CPP.  Some cpp's, eg on HPUX, require
dnl a magic option to avoid problems with ANSI preprocessor commands
dnl like #elif.
dnl FIXME: can't do this because then AC_AIX won't work due to a
dnl circular dependency.
dnl AC_BEFORE([$0], [AC_PROG_CPP])
AC_MSG_CHECKING([for ${CC-cc} option to accept ANSI C])
AC_CACHE_VAL(am_cv_prog_cc_stdc,
[am_cv_prog_cc_stdc=no
ac_save_CC="$CC"
# Don't try gcc -ansi; that turns off useful extensions and
# breaks some systems' header files.
# AIX			-qlanglvl=ansi
# Ultrix and OSF/1	-std1
# HP-UX 10.20 and later	-Ae
# HP-UX older versions	-Aa -D_HPUX_SOURCE
# SVR4			-Xc -D__EXTENSIONS__
for ac_arg in "" -qlanglvl=ansi -std1 -Ae "-Aa -D_HPUX_SOURCE" "-Xc -D__EXTENSIONS__"
do
  CC="$ac_save_CC $ac_arg"
  AC_TRY_COMPILE(
[#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
/* Most of the following tests are stolen from RCS 5.7's src/conf.sh.  */
struct buf { int x; };
FILE * (*rcsopen) (struct buf *, struct stat *, int);
static char *e (p, i)
     char **p;
     int i;
{
  return p[i];
}
static char *f (char * (*g) (char **, int), char **p, ...)
{
  char *s;
  va_list v;
  va_start (v,p);
  s = g (p, va_arg (v,int));
  va_end (v);
  return s;
}
int test (int i, double x);
struct s1 {int (*f) (int a);};
struct s2 {int (*f) (double a);};
int pairnames (int, char **, FILE *(*)(struct buf *, struct stat *, int), int, int);
int argc;
char **argv;
], [
return f (e, argv, 0) != argv[0]  ||  f (e, argv, 1) != argv[1];
],
[am_cv_prog_cc_stdc="$ac_arg"; break])
done
CC="$ac_save_CC"
])
if test -z "$am_cv_prog_cc_stdc"; then
  AC_MSG_RESULT([none needed])
else
  AC_MSG_RESULT([$am_cv_prog_cc_stdc])
fi
case "x$am_cv_prog_cc_stdc" in
  x|xno) ;;
  *) CC="$CC $am_cv_prog_cc_stdc" ;;
esac
])

#serial 2

dnl From Paul Eggert

AC_DEFUN(jm_FUNC_MBRTOWC,
[
  AC_CACHE_CHECK([whether mbrtowc and mbstate_t are properly declared],
    jm_cv_func_mbrtowc,
    [AC_TRY_LINK(
       [@%:@include <wchar.h>],
       [mbstate_t state; return ! (sizeof state && mbrtowc);],
       jm_cv_func_mbrtowc=yes,
       jm_cv_func_mbrtowc=no)])
  if test $jm_cv_func_mbrtowc = yes; then
    AC_DEFINE(HAVE_MBRTOWC, 1,
      [Define to 1 if mbrtowc and mbstate_t are properly declared.])
  fi
])

# serial 8

# From Paul Eggert.

# BeOS 5 has <wchar.h> but does not define mbstate_t,
# so you can't declare an object of that type.
# Check for this incompatibility with Standard C.

# Include stdlib.h first, because otherwise this test would fail on Linux
# (at least glibc-2.1.3) because the "_XOPEN_SOURCE 500" definition elicits
# a syntax error in wchar.h due to the use of undefined __int32_t.

AC_DEFUN(AC_MBSTATE_T,
  [
   AC_CHECK_HEADERS(stdlib.h)

   AC_CACHE_CHECK([for mbstate_t], ac_cv_type_mbstate_t,
    [AC_TRY_COMPILE([
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#include <wchar.h>],
      [mbstate_t x; return sizeof x;],
      ac_cv_type_mbstate_t=yes,
      ac_cv_type_mbstate_t=no)])
   if test $ac_cv_type_mbstate_t = no; then
     AC_DEFINE(mbstate_t, int,
	       [Define to a type if <wchar.h> does not define.])
   fi])

#serial 4

dnl A replacement for autoconf's macro by the same name.  This version
dnl uses `ac_lib' rather than `i' for the loop variable, but more importantly
dnl moves the ACTION-IF-FOUND ([$]3) into the inner `if'-block so that it is
dnl run only if one of the listed libraries ends up being used (and not in
dnl the `none required' case.
dnl I hope it's only temporary while we wait for that version to be fixed.
undefine([AC_SEARCH_LIBS])

# AC_SEARCH_LIBS(FUNCTION, SEARCH-LIBS,
#                [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#                [OTHER-LIBRARIES])
# --------------------------------------------------------
# Search for a library defining FUNC, if it's not already available.
AC_DEFUN(AC_SEARCH_LIBS,
[
  AC_CACHE_CHECK([for library containing $1], [ac_cv_search_$1],
  [
    ac_func_search_save_LIBS=$LIBS
    ac_cv_search_$1=no
    AC_TRY_LINK_FUNC([$1], [ac_cv_search_$1='none required'])
    if test "$ac_cv_search_$1" = no; then
      for ac_lib in $2; do
	LIBS="-l$ac_lib $5 $ac_func_search_save_LIBS"
	AC_TRY_LINK_FUNC([$1], [ac_cv_search_$1="-l$ac_lib"; break])
      done
    fi
    LIBS=$ac_func_search_save_LIBS
  ])

  if test "$ac_cv_search_$1" = no; then :
    $4
  else
    if test "$ac_cv_search_$1" = 'none required'; then :
      $4
    else
      LIBS="$ac_cv_search_$1 $LIBS"
      $3
    fi
  fi
])

#serial 5

dnl From Paul Eggert.

AC_PREREQ(2.13)

# Define uintmax_t to `unsigned long' or `unsigned long long'
# if <inttypes.h> does not exist.

AC_DEFUN(jm_AC_TYPE_UINTMAX_T,
[
  AC_REQUIRE([jm_AC_HEADER_INTTYPES_H])
  if test $jm_ac_cv_header_inttypes_h = no; then
    AC_REQUIRE([jm_AC_TYPE_UNSIGNED_LONG_LONG])
    test $ac_cv_type_unsigned_long_long = yes \
      && ac_type='unsigned long long' \
      || ac_type='unsigned long'
    AC_DEFINE_UNQUOTED(uintmax_t, $ac_type,
[  Define to unsigned long or unsigned long long
   if <inttypes.h> doesn't define.])
  fi
])

#serial 2

dnl From Paul Eggert.

AC_DEFUN(jm_AC_TYPE_UNSIGNED_LONG_LONG,
[
  AC_CACHE_CHECK([for unsigned long long], ac_cv_type_unsigned_long_long,
  [AC_TRY_LINK([unsigned long long ull = 1; int i = 63;],
    [unsigned long long ullmax = (unsigned long long) -1;
     return ull << i | ull >> i | ullmax / ull | ullmax % ull;],
    ac_cv_type_unsigned_long_long=yes,
    ac_cv_type_unsigned_long_long=no)])
  if test $ac_cv_type_unsigned_long_long = yes; then
    AC_DEFINE(HAVE_UNSIGNED_LONG_LONG, 1,
      [Define if you have the unsigned long long type.])
  fi
])

#serial 3

dnl From Paul Eggert.

AC_DEFUN(AC_C_BACKSLASH_A,
[
  AC_CACHE_CHECK([whether backslash-a works in strings], ac_cv_c_backslash_a,
   [AC_TRY_COMPILE([],
     [
#if '\a' == 'a'
      syntax error;
#endif
      char buf['\a' == 'a' ? -1 : 1];
      buf[0] = '\a';
      return buf[0] != "\a"[0];
     ],
     ac_cv_c_backslash_a=yes,
     ac_cv_c_backslash_a=no)])
  if test $ac_cv_c_backslash_a = yes; then
    AC_DEFINE(HAVE_C_BACKSLASH_A, 1,
      [Define if backslash-a works in C strings.])
  fi
])

#serial 1

dnl From Jim Meyering.
dnl Provide lchown on systems that lack it.

AC_DEFUN(jm_FUNC_LCHOWN,
[
  AC_REQUIRE([AC_TYPE_UID_T])
  AC_REPLACE_FUNCS(lchown)
])

#serial 2

# When rmdir fails because the specified directory is not empty, it sets
# errno to some value, usually ENOTEMPTY.  However, on some AIX systems,
# ENOTEMPTY is mistakenly defined to be EEXIST.  To work around this, and
# in general, to avoid depending on the use of any particular symbol, this
# test runs a test to determine the actual numeric value.
AC_DEFUN(fetish_FUNC_RMDIR_NOTEMPTY,
[dnl
  AC_CACHE_CHECK([for rmdir-not-empty errno value],
    fetish_cv_func_rmdir_errno_not_empty,
    [
      # Arrange for deletion of the temporary directory this test creates.
      ac_clean_files="$ac_clean_files confdir2"
      mkdir confdir2; : > confdir2/file
      AC_TRY_RUN([
#include <stdio.h>
#include <errno.h>
#ifndef errno
extern int errno;
#endif
	int main ()
	{
	  FILE *s;
	  int val;
	  rmdir ("confdir2");
	  val = errno;
	  s = fopen ("confdir2/errno", "w");
	  fprintf (s, "%d\n", val);
	  exit (0);
	}
	],
      fetish_cv_func_rmdir_errno_not_empty=`cat confdir2/errno`,
      fetish_cv_func_rmdir_errno_not_empty='configure error in rmdir-errno.m4',
      fetish_cv_func_rmdir_errno_not_empty=ENOTEMPTY
      )
    ]
  )

  AC_DEFINE_UNQUOTED([RMDIR_ERRNO_NOT_EMPTY],
    $fetish_cv_func_rmdir_errno_not_empty,
    [the value to which errno is set when rmdir fails on a nonempty directory])
])

#serial 6

dnl From Jim Meyering.
dnl Determine whether chown accepts arguments of -1 for uid and gid.
dnl If it doesn't, arrange to use the replacement function.
dnl

AC_DEFUN(jm_FUNC_CHOWN,
[AC_REQUIRE([AC_TYPE_UID_T])dnl
 test -z "$ac_cv_header_unistd_h" \
   && AC_CHECK_HEADERS(unistd.h)
 AC_CACHE_CHECK([for working chown], jm_cv_func_working_chown,
  [AC_TRY_RUN([
#   include <sys/types.h>
#   include <sys/stat.h>
#   include <fcntl.h>
#   ifdef HAVE_UNISTD_H
#    include <unistd.h>
#   endif

    int
    main ()
    {
      char *f = "conftest.chown";
      struct stat before, after;

      if (creat (f, 0600) < 0)
        exit (1);
      if (stat (f, &before) < 0)
        exit (1);
      if (chown (f, (uid_t) -1, (gid_t) -1) == -1)
        exit (1);
      if (stat (f, &after) < 0)
        exit (1);
      exit ((before.st_uid == after.st_uid
	     && before.st_gid == after.st_gid) ? 0 : 1);
    }
	      ],
	     jm_cv_func_working_chown=yes,
	     jm_cv_func_working_chown=no,
	     dnl When crosscompiling, assume chown is broken.
	     jm_cv_func_working_chown=no)
  ])
  if test $jm_cv_func_working_chown = no; then
    AC_LIBOBJ(chown)
    AC_DEFINE_UNQUOTED(chown, rpl_chown,
      [Define to rpl_chown if the replacement function should be used.])
  fi
])

#serial 7

dnl From Jim Meyering.
dnl A wrapper around AC_FUNC_MKTIME.

AC_DEFUN(jm_FUNC_MKTIME,
[AC_REQUIRE([AC_FUNC_MKTIME])dnl

 dnl mktime.c uses localtime_r if it exists.  Check for it.
 AC_CHECK_FUNCS(localtime_r)

 if test $ac_cv_func_working_mktime = no; then
   AC_DEFINE_UNQUOTED(mktime, rpl_mktime,
    [Define to rpl_mktime if the replacement function should be used.])
 fi
])

#serial 6

dnl From Jim Meyering.
dnl Determine whether lstat has the bug that it succeeds when given the
dnl zero-length file name argument.  The lstat from SunOS4.1.4 and the Hurd
dnl (as of 1998-11-01) do this.
dnl
dnl If it does, then define HAVE_LSTAT_EMPTY_STRING_BUG and arrange to
dnl compile the wrapper function.
dnl

AC_DEFUN(jm_FUNC_LSTAT,
[
 AC_REQUIRE([AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK])
 AC_CACHE_CHECK([whether lstat accepts an empty string],
  jm_cv_func_lstat_empty_string_bug,
  [AC_TRY_RUN([
#   include <sys/types.h>
#   include <sys/stat.h>

    int
    main ()
    {
      struct stat sbuf;
      exit (lstat ("", &sbuf) ? 1 : 0);
    }
	  ],
	 jm_cv_func_lstat_empty_string_bug=yes,
	 jm_cv_func_lstat_empty_string_bug=no,
	 dnl When crosscompiling, assume lstat is broken.
	 jm_cv_func_lstat_empty_string_bug=yes)
  ])
  if test $jm_cv_func_lstat_empty_string_bug = yes; then
    AC_LIBOBJ(lstat)
    AC_DEFINE_UNQUOTED(HAVE_LSTAT_EMPTY_STRING_BUG, 1,
[Define if lstat has the bug that it succeeds when given the zero-length
   file name argument.  The lstat from SunOS4.1.4 and the Hurd as of 1998-11-01)
   do this. ])
  fi
])

#serial 6

dnl From Jim Meyering.
dnl Determine whether stat has the bug that it succeeds when given the
dnl zero-length file name argument.  The stat from SunOS4.1.4 and the Hurd
dnl (as of 1998-11-01) do this.
dnl
dnl If it does, then define HAVE_STAT_EMPTY_STRING_BUG and arrange to
dnl compile the wrapper function.
dnl

AC_DEFUN(jm_FUNC_STAT,
[
 AC_REQUIRE([AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK])
 AC_CACHE_CHECK([whether stat accepts an empty string],
  jm_cv_func_stat_empty_string_bug,
  [AC_TRY_RUN([
#   include <sys/types.h>
#   include <sys/stat.h>

    int
    main ()
    {
      struct stat sbuf;
      exit (stat ("", &sbuf) ? 1 : 0);
    }
	  ],
	 jm_cv_func_stat_empty_string_bug=yes,
	 jm_cv_func_stat_empty_string_bug=no,
	 dnl When crosscompiling, assume stat is broken.
	 jm_cv_func_stat_empty_string_bug=yes)
  ])
  if test $jm_cv_func_stat_empty_string_bug = yes; then
    AC_LIBOBJ(stat)
    AC_DEFINE_UNQUOTED(HAVE_STAT_EMPTY_STRING_BUG, 1,
[Define if stat has the bug that it succeeds when given the zero-length
   file name argument.  The stat from SunOS4.1.4 and the Hurd as of 1998-11-01)
   do this. ])
  fi
])

#serial 4

dnl From Jim Meyering.
dnl Determine whether realloc works when both arguments are 0.
dnl If it doesn't, arrange to use the replacement function.
dnl

AC_DEFUN(jm_FUNC_REALLOC,
[
 dnl xmalloc.c requires that this symbol be defined so it doesn't
 dnl mistakenly use a broken realloc -- as it might if this test were omitted.
 AC_DEFINE_UNQUOTED(HAVE_DONE_WORKING_REALLOC_CHECK, 1,
                    [Define if the realloc check has been performed. ])

 AC_CACHE_CHECK([for working realloc], jm_cv_func_working_realloc,
  [AC_TRY_RUN([
    char *realloc ();
    int
    main ()
    {
      exit (realloc (0, 0) ? 0 : 1);
    }
	  ],
	 jm_cv_func_working_realloc=yes,
	 jm_cv_func_working_realloc=no,
	 dnl When crosscompiling, assume realloc is broken.
	 jm_cv_func_working_realloc=no)
  ])
  if test $jm_cv_func_working_realloc = no; then
    AC_LIBOBJ(realloc)
    AC_DEFINE_UNQUOTED(realloc, rpl_realloc,
      [Define to rpl_realloc if the replacement function should be used.])
  fi
])

#serial 4

dnl From Jim Meyering.
dnl Determine whether malloc accepts 0 as its argument.
dnl If it doesn't, arrange to use the replacement function.
dnl

AC_DEFUN(jm_FUNC_MALLOC,
[
 dnl xmalloc.c requires that this symbol be defined so it doesn't
 dnl mistakenly use a broken malloc -- as it might if this test were omitted.
 AC_DEFINE_UNQUOTED(HAVE_DONE_WORKING_MALLOC_CHECK, 1,
                    [Define if the malloc check has been performed. ])

 AC_CACHE_CHECK([for working malloc], jm_cv_func_working_malloc,
  [AC_TRY_RUN([
    char *malloc ();
    int
    main ()
    {
      exit (malloc (0) ? 0 : 1);
    }
	  ],
	 jm_cv_func_working_malloc=yes,
	 jm_cv_func_working_malloc=no,
	 dnl When crosscompiling, assume malloc is broken.
	 jm_cv_func_working_malloc=no)
  ])
  if test $jm_cv_func_working_malloc = no; then
    AC_LIBOBJ(malloc)
    AC_DEFINE_UNQUOTED(malloc, rpl_malloc,
      [Define to rpl_malloc if the replacement function should be used.])
  fi
])

#serial 7

dnl From Jim Meyering.
dnl Check for the nanosleep function.
dnl If not found, use the supplied replacement.
dnl

AC_DEFUN(jm_FUNC_NANOSLEEP,
[
 nanosleep_save_libs=$LIBS

 # Solaris 2.5.1 needs -lposix4 to get the nanosleep function.
 # Solaris 7 prefers the library name -lrt to the obsolescent name -lposix4.
 AC_SEARCH_LIBS(nanosleep, [rt posix4], [LIB_NANOSLEEP=$ac_cv_search_nanosleep])
 AC_SUBST(LIB_NANOSLEEP)

 AC_CACHE_CHECK([whether nanosleep works],
  jm_cv_func_nanosleep_works,
  [
   AC_REQUIRE([AC_HEADER_TIME])
   AC_TRY_RUN([
#   if TIME_WITH_SYS_TIME
#    include <sys/time.h>
#    include <time.h>
#   else
#    if HAVE_SYS_TIME_H
#     include <sys/time.h>
#    else
#     include <time.h>
#    endif
#   endif

    int
    main ()
    {
      struct timespec ts_sleep, ts_remaining;
      ts_sleep.tv_sec = 0;
      ts_sleep.tv_nsec = 1;
      exit (nanosleep (&ts_sleep, &ts_remaining) == 0 ? 0 : 1);
    }
	  ],
	 jm_cv_func_nanosleep_works=yes,
	 jm_cv_func_nanosleep_works=no,
	 dnl When crosscompiling, assume the worst.
	 jm_cv_func_nanosleep_works=no)
  ])
  if test $jm_cv_func_nanosleep_works = no; then
    AC_LIBOBJ(nanosleep)
    AC_DEFINE_UNQUOTED(nanosleep, rpl_nanosleep,
      [Define to rpl_nanosleep if the replacement function should be used.])
  fi

 LIBS=$nanosleep_save_libs
])

#serial 3

dnl SunOS's readdir is broken in such a way that rm.c has to add extra code
dnl to test whether a NULL return value really means there are no more files
dnl in the directory.
dnl
dnl Detect the problem by creating a directory containing 300 files (254 not
dnl counting . and .. is the minimum) and see if a loop doing `readdir; unlink'
dnl removes all of them.
dnl
dnl Define HAVE_WORKING_READDIR if readdir does *not* have this problem.

dnl Written by Jim Meyering.

AC_DEFUN(jm_FUNC_READDIR,
[dnl
AC_REQUIRE([AC_HEADER_DIRENT])
AC_CHECK_HEADERS(string.h)
AC_CACHE_CHECK([for working readdir], jm_cv_func_working_readdir,
  [dnl
  # Arrange for deletion of the temporary directory this test creates, in
  # case the test itself fails to delete everything -- as happens on Sunos.
  ac_clean_files="$ac_clean_files conf-dir"

  AC_TRY_RUN(
[#   include <stdio.h>
#   include <sys/types.h>
#   if HAVE_STRING_H
#    include <string.h>
#   endif

#   ifdef HAVE_DIRENT_H
#    include <dirent.h>
#    define NLENGTH(direct) (strlen((direct)->d_name))
#   else /* not HAVE_DIRENT_H */
#    define dirent direct
#    define NLENGTH(direct) ((direct)->d_namlen)
#    ifdef HAVE_SYS_NDIR_H
#     include <sys/ndir.h>
#    endif /* HAVE_SYS_NDIR_H */
#    ifdef HAVE_SYS_DIR_H
#     include <sys/dir.h>
#    endif /* HAVE_SYS_DIR_H */
#    ifdef HAVE_NDIR_H
#     include <ndir.h>
#    endif /* HAVE_NDIR_H */
#   endif /* HAVE_DIRENT_H */

#   define DOT_OR_DOTDOT(Basename) \
     (Basename[0] == '.' && (Basename[1] == '\0' \
			     || (Basename[1] == '.' && Basename[2] == '\0')))

    static void
    create_300_file_dir (const char *dir)
    {
      int i;

      if (mkdir (dir, 0700))
	abort ();
      if (chdir (dir))
	abort ();

      for (i = 0; i < 300; i++)
	{
	  char file_name[4];
	  FILE *out;

	  sprintf (file_name, "%03d", i);
	  out = fopen (file_name, "w");
	  if (!out)
	    abort ();
	  if (fclose (out) == EOF)
	    abort ();
	}

      if (chdir (".."))
	abort ();
    }

    static void
    remove_dir (const char *dir)
    {
      DIR *dirp;

      if (chdir (dir))
	abort ();

      dirp = opendir (".");
      if (dirp == NULL)
	abort ();

      while (1)
	{
	  struct dirent *dp = readdir (dirp);
	  if (dp == NULL)
	    break;

	  if (DOT_OR_DOTDOT (dp->d_name))
	    continue;

	  if (unlink (dp->d_name))
	    abort ();
	}
      closedir (dirp);

      if (chdir (".."))
	abort ();

      if (rmdir (dir))
	exit (1);
    }

    int
    main ()
    {
      const char *dir = "conf-dir";
      create_300_file_dir (dir);
      remove_dir (dir);
      exit (0);
    }],
  jm_cv_func_working_readdir=yes,
  jm_cv_func_working_readdir=no,
  jm_cv_func_working_readdir=no)])

  if test $jm_cv_func_working_readdir = yes; then
    AC_DEFINE_UNQUOTED(HAVE_WORKING_READDIR, 1,
[Define if readdir is found to work properly in some unusual cases. ])
  fi
])

#serial 6

AC_DEFUN(jm_FUNC_MEMCMP,
[AC_REQUIRE([AC_FUNC_MEMCMP])dnl
 if test $ac_cv_func_memcmp_working = no; then
   AC_DEFINE_UNQUOTED(memcmp, rpl_memcmp,
     [Define to rpl_memcmp if the replacement function should be used.])
 fi
])

#serial 4

dnl From Jim Meyering.
dnl
dnl See if the glibc *_unlocked I/O macros are available.
dnl Use only those *_unlocked macros that are declared.
dnl

AC_DEFUN(jm_FUNC_GLIBC_UNLOCKED_IO,
  [
    # Kludge (not executed) to make autoheader do the right thing.
    if test a = b; then
      AC_CHECK_DECLS([clearerr_unlocked, feof_unlocked, ferror_unlocked,
	fflush_unlocked, fputc_unlocked, fread_unlocked, fwrite_unlocked,
	getc_unlocked, getchar_unlocked, putc_unlocked, putchar_unlocked])
    fi

    io_functions='clearerr_unlocked feof_unlocked ferror_unlocked
    fflush_unlocked fputc_unlocked fread_unlocked fwrite_unlocked
    getc_unlocked getchar_unlocked putc_unlocked putchar_unlocked'
    for jm_io_func in $io_functions; do
      # Check for the existence of each function only if its declared.
      # Otherwise, we'd get the Solaris5.5.1 functions that are not
      # declared, and that have been removed from Solaris5.6.  The resulting
      # 5.5.1 binaries would not run on 5.6 due to shared library differences.
      AC_CHECK_DECLS([$jm_io_func],
		     jm_declared=yes,
		     jm_declared=no,
		     [#include <stdio.h>])
      if test $jm_declared = yes; then
        AC_CHECK_FUNCS($jm_io_func)
      fi
    done
  ]
)

#serial 3

dnl Determine whether to add fnmatch.o to LIBOBJS and to
dnl define fnmatch to rpl_fnmatch.
dnl

AC_DEFUN(jm_FUNC_FNMATCH,
[
  AC_REQUIRE([AM_GLIBC])
  AC_FUNC_FNMATCH
  if test $ac_cv_func_fnmatch_works = no \
      && test $ac_cv_gnu_library = no; then
    AC_LIBOBJ(fnmatch)
    AC_DEFINE_UNQUOTED(fnmatch, rpl_fnmatch,
      [Define to rpl_fnmatch if the replacement function should be used.])
  fi
])

#serial 2

dnl From Gordon Matzigkeit.
dnl Test for the GNU C Library.
dnl FIXME: this should migrate into libit.

AC_DEFUN(AM_GLIBC,
  [
    AC_CACHE_CHECK(whether we are using the GNU C Library,
      ac_cv_gnu_library,
      [AC_EGREP_CPP([Thanks for using GNU],
	[
#include <features.h>
#ifdef __GNU_LIBRARY__
  Thanks for using GNU
#endif
	],
	ac_cv_gnu_library=yes,
	ac_cv_gnu_library=no)
      ]
    )
    AC_CACHE_CHECK(for version 2 of the GNU C Library,
      ac_cv_glibc,
      [AC_EGREP_CPP([Thanks for using GNU too],
	[
#include <features.h>
#ifdef __GLIBC__
  Thanks for using GNU too
#endif
	],
	ac_cv_glibc=yes, ac_cv_glibc=no)
      ]
    )
  ]
)

#serial 2

dnl Written by Jim Meyering

AC_DEFUN(jm_FUNC_GROUP_MEMBER,
  [
    dnl Do this replacement check manually because I want the hyphen
    dnl (not the underscore) in the filename.
    AC_CHECK_FUNC(group_member, , [AC_LIBOBJ(group-member)])
  ]
)

#serial 4

dnl From Jim Meyering.
dnl
dnl Check whether putenv ("FOO") removes FOO from the environment.
dnl The putenv in libc on at least SunOS 4.1.4 does *not* do that.
dnl

AC_DEFUN(jm_FUNC_PUTENV,
[AC_CACHE_CHECK([for SVID conformant putenv], jm_cv_func_svid_putenv,
  [AC_TRY_RUN([
    int
    main ()
    {
      /* Put it in env.  */
      if (putenv ("CONFTEST_putenv=val"))
        exit (1);

      /* Try to remove it.  */
      if (putenv ("CONFTEST_putenv"))
        exit (1);

      /* Make sure it was deleted.  */
      if (getenv ("CONFTEST_putenv") != 0)
        exit (1);

      exit (0);
    }
	      ],
	     jm_cv_func_svid_putenv=yes,
	     jm_cv_func_svid_putenv=no,
	     dnl When crosscompiling, assume putenv is broken.
	     jm_cv_func_svid_putenv=no)
  ])
  if test $jm_cv_func_svid_putenv = no; then
    AC_LIBOBJ(putenv)
    AC_DEFINE_UNQUOTED(putenv, rpl_putenv,
      [Define to rpl_putenv if the replacement function should be used.])
  fi
])

#serial 3

AC_DEFUN(jm_AFS,
  AC_MSG_CHECKING(for AFS)
  if test -d /afs; then
    AC_DEFINE(AFS, 1, [Define if you have the Andrew File System.])
    ac_result=yes
  else
    ac_result=no
  fi
  AC_MSG_RESULT($ac_result)
)

#serial 3

# autoconf tests required for use of xstrtoumax.c

AC_DEFUN(jm_AC_PREREQ_XSTRTOUMAX,
[
  AC_REQUIRE([jm_AC_TYPE_UINTMAX_T])
  AC_REQUIRE([jm_AC_HEADER_INTTYPES_H])
  AC_REQUIRE([jm_AC_TYPE_UNSIGNED_LONG_LONG])
  AC_CHECK_DECLS([strtoul, strtoull])
  AC_CHECK_HEADERS(limits.h stdlib.h)

  AC_CACHE_CHECK([whether <inttypes.h> defines strtoumax as a macro],
    jm_cv_func_strtoumax_macro,
    AC_EGREP_CPP([inttypes_h_defines_strtoumax], [#include <inttypes.h>
#ifdef strtoumax
 inttypes_h_defines_strtoumax
#endif],
      jm_cv_func_strtoumax_macro=yes,
      jm_cv_func_strtoumax_macro=no))

  if test "$jm_cv_func_strtoumax_macro" != yes; then
    AC_REPLACE_FUNCS(strtoumax)
  fi

  dnl We don't need (and can't compile) the replacement strtoull
  dnl unless the type `unsigned long long' exists.
  dnl Also, only the replacement strtoumax invokes strtoull,
  dnl so we need the replacement strtoull only if strtoumax does not exist.
  case "$ac_cv_type_unsigned_long_long,$jm_cv_func_strtoumax_macro,$ac_cv_func_strtoumax" in
    yes,no,no)
      AC_REPLACE_FUNCS(strtoull strtol)
      ;;
  esac

  case "$jm_cv_func_strtoumax_macro,$ac_cv_func_strtoumax" in
    no,no)
      AC_REPLACE_FUNCS(strtoul strtol)
      ;;
  esac

])

#serial 2
dnl Run a program to determine whether whether link(2) follows symlinks.
dnl Set LINK_FOLLOWS_SYMLINKS accordingly.

AC_DEFUN(jm_AC_FUNC_LINK_FOLLOWS_SYMLINK,
[dnl
  AC_CACHE_CHECK(
    [whether link(2) dereferences a symlink specified with a trailing slash],
		 jm_ac_cv_func_link_follows_symlink,
  [
    dnl poor-man's AC_REQUIRE: FIXME: repair this once autoconf-3 provides
    dnl the appropriate framework.
    test -z "$ac_cv_header_unistd_h" \
      && AC_CHECK_HEADERS(unistd.h)

    # Create a regular file.
    echo > conftest.file
    AC_TRY_RUN(
      [
#       include <sys/types.h>
#       include <sys/stat.h>
#       ifdef HAVE_UNISTD_H
#        include <unistd.h>
#       endif

#       define SAME_INODE(Stat_buf_1, Stat_buf_2) \
	  ((Stat_buf_1).st_ino == (Stat_buf_2).st_ino \
	   && (Stat_buf_1).st_dev == (Stat_buf_2).st_dev)

	int
	main ()
	{
	  const char *file = "conftest.file";
	  const char *sym = "conftest.sym";
	  const char *hard = "conftest.hard";
	  struct stat sb_file, sb_hard;

	  /* Create a symlink to the regular file. */
	  if (symlink (file, sym))
	    abort ();

	  /* Create a hard link to that symlink.  */
	  if (link (sym, hard))
	    abort ();

	  if (lstat (hard, &sb_hard))
	    abort ();
	  if (lstat (file, &sb_file))
	    abort ();

	  /* If the dev/inode of hard and file are the same, then
	     the link call followed the symlink.  */
	  return SAME_INODE (sb_hard, sb_file) ? 0 : 1;
	}
      ],
      jm_ac_cv_func_link_follows_symlink=yes,
      jm_ac_cv_func_link_follows_symlink=no,
      jm_ac_cv_func_link_follows_symlink=yes dnl We're cross compiling.
    )
  ])
  if test $jm_ac_cv_func_link_follows_symlink = yes; then
    AC_DEFINE(LINK_FOLLOWS_SYMLINKS, 1,
      [Define if `link(2)' dereferences symbolic links.])
  fi
])

# From Jim Meyering.  Use this if you use the GNU error.[ch].
# FIXME: Migrate into libit

AC_DEFUN([AM_FUNC_ERROR_AT_LINE],
[AC_CACHE_CHECK([for error_at_line], am_cv_lib_error_at_line,
 [AC_TRY_LINK([],[error_at_line(0, 0, "", 0, "");],
              am_cv_lib_error_at_line=yes,
	      am_cv_lib_error_at_line=no)])
 if test $am_cv_lib_error_at_line = no; then
   LIBOBJS="$LIBOBJS error.$ac_objext"
 fi
 AC_SUBST(LIBOBJS)dnl
])

#serial 15

dnl This macro is intended to be used solely in this file.
dnl These are the prerequisite macros for GNU's strftime.c replacement.
AC_DEFUN(_jm_STRFTIME_PREREQS,
[
 dnl strftime.c uses localtime_r and the underyling system strftime
 dnl if they exist.
 AC_CHECK_FUNCS(localtime_r strftime)

 AC_CHECK_HEADERS(limits.h)
 AC_CHECK_FUNCS(bcopy tzset mempcpy memcpy memset)

 # This defines (or not) HAVE_TZNAME and HAVE_TM_ZONE.
 AC_STRUCT_TIMEZONE

 AC_CHECK_FUNCS(mblen mbrlen)

 AC_CHECK_MEMBER([struct tm.tm_gmtoff],
                 [AC_DEFINE(HAVE_TM_GMTOFF, 1,
                            [Define if struct tm has the tm_gmtoff member.])],
                 ,
                 [#include <time.h>])
])

dnl Determine if the strftime function has all the features of the GNU one.
dnl
dnl From Jim Meyering.
dnl
AC_DEFUN(jm_FUNC_GNU_STRFTIME,
[AC_REQUIRE([AC_HEADER_TIME])dnl

 _jm_STRFTIME_PREREQS

 AC_REQUIRE([AC_C_CONST])dnl
 AC_REQUIRE([AC_HEADER_STDC])dnl
 AC_CHECK_HEADERS(sys/time.h)
 AC_CACHE_CHECK([for working GNU strftime], jm_cv_func_working_gnu_strftime,
  [AC_TRY_RUN(
[ /* Ulrich Drepper provided parts of the test program.  */
#if STDC_HEADERS
# include <stdlib.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

static int
compare (const char *fmt, const struct tm *tm, const char *expected)
{
  char buf[99];
  strftime (buf, 99, fmt, tm);
  if (strcmp (buf, expected))
    {
#ifdef SHOW_FAILURES
      printf ("fmt: \"%s\", expected \"%s\", got \"%s\"\n",
	      fmt, expected, buf);
#endif
      return 1;
    }
  return 0;
}

int
main ()
{
  int n_fail = 0;
  struct tm *tm;
  time_t t = 738367; /* Fri Jan  9 13:06:07 1970 */
  tm = gmtime (&t);

  /* Undefine this in case the configure-time putenv test has defined it
     to something else.  The use we make of this function here doesn't
     require the added functionality of the replacement one.  */
#undef putenv

  /* This is necessary to make strftime give consistent zone strings and
     e.g., seconds since the epoch (%s).  */
  putenv ("TZ=GMT0");

#undef CMP
#define CMP(Fmt, Expected) n_fail += compare ((Fmt), tm, (Expected))

  CMP ("%-m", "1");		/* GNU */
  CMP ("%A", "Friday");
  CMP ("%^A", "FRIDAY");	/* The ^ is a GNU extension.  */
  CMP ("%B", "January");
  CMP ("%^B", "JANUARY");
  CMP ("%C", "19");		/* POSIX.2 */
  CMP ("%D", "01/09/70");	/* POSIX.2 */
  CMP ("%F", "1970-01-09");
  CMP ("%G", "1970");		/* GNU */
  CMP ("%H", "13");
  CMP ("%I", "01");
  CMP ("%M", "06");
  CMP ("%M", "06");
  CMP ("%R", "13:06");		/* POSIX.2 */
  CMP ("%S", "07");
  CMP ("%T", "13:06:07");	/* POSIX.2 */
  CMP ("%U", "01");
  CMP ("%V", "02");
  CMP ("%W", "01");
  CMP ("%X", "13:06:07");
  CMP ("%Y", "1970");
  CMP ("%Z", "GMT");
  CMP ("%_m", " 1");		/* GNU */
  CMP ("%a", "Fri");
  CMP ("%^a", "FRI");
  CMP ("%b", "Jan");
  CMP ("%^b", "JAN");
  CMP ("%c", "Fri Jan  9 13:06:07 1970");
  CMP ("%^c", "FRI JAN  9 13:06:07 1970");
  CMP ("%d", "09");
  CMP ("%e", " 9");		/* POSIX.2 */
  CMP ("%g", "70");		/* GNU */
  CMP ("%h", "Jan");		/* POSIX.2 */
  CMP ("%^h", "JAN");
  CMP ("%j", "009");
  CMP ("%k", "13");		/* GNU */
  CMP ("%l", " 1");		/* GNU */
  CMP ("%m", "01");
  CMP ("%n", "\n");		/* POSIX.2 */
  CMP ("%p", "PM");
  CMP ("%r", "01:06:07 PM");	/* POSIX.2 */
  CMP ("%s", "738367");		/* GNU */
  CMP ("%t", "\t");		/* POSIX.2 */
  CMP ("%u", "5");		/* POSIX.2 */
  CMP ("%w", "5");
  CMP ("%x", "01/09/70");
  CMP ("%y", "70");
  CMP ("%z", "+0000");		/* GNU */

  exit (n_fail ? 1 : 0);
}],
	     jm_cv_func_working_gnu_strftime=yes,
             jm_cv_func_working_gnu_strftime=no,
	     dnl When crosscompiling, assume strftime is missing or broken.
	     jm_cv_func_working_gnu_strftime=no)
  ])
  if test $jm_cv_func_working_gnu_strftime = no; then
    AC_LIBOBJ(strftime)
    AC_DEFINE_UNQUOTED(strftime, gnu_strftime,
      [Define to gnu_strftime if the replacement function should be used.])
  fi
])

AC_DEFUN(jm_FUNC_STRFTIME,
[
  _jm_STRFTIME_PREREQS
  AC_REPLACE_FUNCS(strftime)
])

#serial 1

dnl From Jim Meyering
dnl Using code from emacs, based on suggestions from Paul Eggert
dnl and Ulrich Drepper.

dnl Find out how to determine the number of pending output bytes on a stream.
dnl glibc (2.1.93 and newer) and Solaris provide __fpending.  On other systems,
dnl we have to grub around in the FILE struct.

AC_DEFUN(jm_FUNC_FPENDING,
[
  AC_CHECK_HEADERS(stdio_ext.h)
  AC_REPLACE_FUNCS([__fpending])
  fp_headers='
#     if HAVE_STDIO_EXT_H
#      include <stdio_ext.h>
#     endif
'
  AC_CHECK_DECLS([__fpending], , , $fp_headers)
  if test $ac_cv_func___fpending = no; then
    AC_CACHE_CHECK(
	      [how to determine the number of pending output bytes on a stream],
		   ac_cv_sys_pending_output_n_bytes,
      [
        fp_save_DEFS=$DEFS
	for ac_expr in						\
								\
	    '# glibc2'						\
	    'fp->_IO_write_ptr - fp->_IO_write_base'		\
								\
	    '# traditional Unix'				\
	    'fp->_ptr - fp->_base'				\
								\
	    '# BSD'						\
	    'fp->_p - fp->_bf._base'				\
								\
	    '# SCO, Unixware'					\
	    'fp->__ptr - fp->__base'				\
								\
	    '# old glibc?'					\
	    'fp->__bufp - fp->__buffer'				\
								\
	    '# old glibc iostream?'				\
	    'fp->_pptr - fp->_pbase'				\
								\
	    '# VMS'						\
	    '(*fp)->_ptr - (*fp)->_base'			\
								\
	    '# e.g., DGUX R4.11; the info is not available'	\
	    1							\
	    ; do

	  # Skip each embedded comment.
	  case "$ac_expr" in '#'*) continue;; esac

	  DEFS="$DEFS -DPENDING_OUTPUT_N_BYTES=$ac_expr"
	  AC_TRY_COMPILE(
	    [#include <stdio.h>
	    ],
	    [FILE *fp = stdin; (void) ($ac_expr);],
	    fp_done=yes
	  )
	  DEFS=$fp_save_DEFS
	  test "$fp_done" = yes && break
	done

	ac_cv_sys_pending_output_n_bytes=$ac_expr
      ]
    )
    AC_DEFINE_UNQUOTED(PENDING_OUTPUT_N_BYTES,
      $ac_cv_sys_pending_output_n_bytes,
      [the number of pending output bytes on stream `fp'])
  fi
])

#serial 4

dnl From Jim Meyering.
dnl
dnl Invoking code should check $GETGROUPS_LIB something like this:
dnl  jm_FUNC_GETGROUPS
dnl  test -n "$GETGROUPS_LIB" && LIBS="$GETGROUPS_LIB $LIBS"
dnl

AC_DEFUN(jm_FUNC_GETGROUPS,
[AC_REQUIRE([AC_TYPE_GETGROUPS])dnl
 AC_REQUIRE([AC_TYPE_SIZE_T])dnl
 AC_CHECK_FUNCS(getgroups)

 # If we don't yet have getgroups, see if it's in -lbsd.
 # This is reported to be necessary on an ITOS 3000WS running SEIUX 3.1.
 if test $ac_cv_func_getgroups = no; then
   jm_cv_sys_getgroups_saved_lib="$LIBS"
   AC_CHECK_LIB(bsd, getgroups, [GETGROUPS_LIB=-lbsd])
   LIBS="$jm_cv_sys_getgroups_saved_lib"
 fi

 # Run the program to test the functionality of the system-supplied
 # getgroups function only if there is such a function.
 if test $ac_cv_func_getgroups = yes; then
   AC_CACHE_CHECK([for working getgroups], jm_cv_func_working_getgroups,
    [AC_TRY_RUN([
      int
      main ()
      {
	/* On Ultrix 4.3, getgroups (0, 0) always fails.  */
	exit (getgroups (0, 0) == -1 ? 1 : 0);
      }
		],
	       jm_cv_func_working_getgroups=yes,
	       jm_cv_func_working_getgroups=no,
	       dnl When crosscompiling, assume getgroups is broken.
	       jm_cv_func_working_getgroups=no)
    ])
    if test $jm_cv_func_working_getgroups = no; then
      AC_LIBOBJ(getgroups)
      AC_DEFINE_UNQUOTED(getgroups, rpl_getgroups,
	[Define as rpl_getgroups if getgroups doesn't work right.])
    fi
  fi
])

#serial 8

# A replacement for autoconf's macro by the same name.  This version
# accepts an optional argument specifying the name of the $srcdir-relative
# directory in which the file getloadavg.c may be found.  It is unusual
# (but justified, imho) that this file is required at ./configure time.

undefine([AC_FUNC_GETLOADAVG])

# AC_FUNC_GETLOADAVG
# ------------------
AC_DEFUN([AC_FUNC_GETLOADAVG],
[ac_have_func=no # yes means we've found a way to get the load average.

# By default, expect to find getloadavg.c in $srcdir/.
ac_lib_dir_getloadavg=$srcdir
# But if there's an argument, DIR, expect to find getloadavg.c in $srcdir/DIR.
m4_ifval([$1], [ac_lib_dir_getloadavg=$srcdir/$1])
# Make sure getloadavg.c is where it belongs, at ./configure-time.
test -f $ac_lib_dir_getloadavg/getloadavg.c \
  || AC_MSG_ERROR([getloadavg.c is not in $ac_lib_dir_getloadavg])
# FIXME: Add an autoconf-time test, too?

ac_save_LIBS=$LIBS

# Check for getloadavg, but be sure not to touch the cache variable.
(AC_CHECK_FUNC(getloadavg, exit 0, exit 1)) && ac_have_func=yes

# On HPUX9, an unprivileged user can get load averages through this function.
AC_CHECK_FUNCS(pstat_getdynamic)

# Solaris has libkstat which does not require root.
AC_CHECK_LIB(kstat, kstat_open)
test $ac_cv_lib_kstat_kstat_open = yes && ac_have_func=yes

# Some systems with -lutil have (and need) -lkvm as well, some do not.
# On Solaris, -lkvm requires nlist from -lelf, so check that first
# to get the right answer into the cache.
# For kstat on solaris, we need libelf to force the definition of SVR4 below.
if test $ac_have_func = no; then
  AC_CHECK_LIB(elf, elf_begin, LIBS="-lelf $LIBS")
fi
if test $ac_have_func = no; then
  AC_CHECK_LIB(kvm, kvm_open, LIBS="-lkvm $LIBS")
  # Check for the 4.4BSD definition of getloadavg.
  AC_CHECK_LIB(util, getloadavg,
    [LIBS="-lutil $LIBS" ac_have_func=yes ac_cv_func_getloadavg_setgid=yes])
fi

if test $ac_have_func = no; then
  # There is a commonly available library for RS/6000 AIX.
  # Since it is not a standard part of AIX, it might be installed locally.
  ac_getloadavg_LIBS=$LIBS
  LIBS="-L/usr/local/lib $LIBS"
  AC_CHECK_LIB(getloadavg, getloadavg,
               [LIBS="-lgetloadavg $LIBS"], [LIBS=$ac_getloadavg_LIBS])
fi

# Make sure it is really in the library, if we think we found it,
# otherwise set up the replacement function.
AC_CHECK_FUNCS(getloadavg, [],
               [_AC_LIBOBJ_GETLOADAVG])

# Some definitions of getloadavg require that the program be installed setgid.
AC_CACHE_CHECK(whether getloadavg requires setgid,
               ac_cv_func_getloadavg_setgid,
[AC_EGREP_CPP([Yowza Am I SETGID yet],
[#include "$ac_lib_dir_getloadavg/getloadavg.c"
#ifdef LDAV_PRIVILEGED
Yowza Am I SETGID yet
@%:@endif],
              ac_cv_func_getloadavg_setgid=yes,
              ac_cv_func_getloadavg_setgid=no)])
if test $ac_cv_func_getloadavg_setgid = yes; then
  NEED_SETGID=true
  AC_DEFINE(GETLOADAVG_PRIVILEGED, 1,
            [Define if the `getloadavg' function needs to be run setuid
             or setgid.])
else
  NEED_SETGID=false
fi
AC_SUBST(NEED_SETGID)dnl

if test $ac_cv_func_getloadavg_setgid = yes; then
  AC_CACHE_CHECK(group of /dev/kmem, ac_cv_group_kmem,
[ # On Solaris, /dev/kmem is a symlink.  Get info on the real file.
  ac_ls_output=`ls -lgL /dev/kmem 2>/dev/null`
  # If we got an error (system does not support symlinks), try without -L.
  test -z "$ac_ls_output" && ac_ls_output=`ls -lg /dev/kmem`
  ac_cv_group_kmem=`echo $ac_ls_output \
    | sed -ne ['s/[ 	][ 	]*/ /g;
	       s/^.[sSrwx-]* *[0-9]* *\([^0-9]*\)  *.*/\1/;
	       / /s/.* //;p;']`
])
  AC_SUBST(KMEM_GROUP, $ac_cv_group_kmem)dnl
fi
if test "x$ac_save_LIBS" = x; then
  GETLOADAVG_LIBS=$LIBS
else
  GETLOADAVG_LIBS=`echo "$LIBS" | sed "s!$ac_save_LIBS!!"`
fi
LIBS=$ac_save_LIBS

AC_SUBST(GETLOADAVG_LIBS)dnl
])# AC_FUNC_GETLOADAVG

#serial 4

AC_PREREQ(2.13)

AC_DEFUN(jm_SYS_PROC_UPTIME,
[ dnl Require AC_PROG_CC to see if we're cross compiling.
  AC_REQUIRE([AC_PROG_CC])
  AC_CACHE_CHECK([for /proc/uptime], jm_cv_have_proc_uptime,
  [jm_cv_have_proc_uptime=no
    test -f /proc/uptime \
      && test "$cross_compiling" = no \
      && cat < /proc/uptime >/dev/null 2>/dev/null \
      && jm_cv_have_proc_uptime=yes])
  if test $jm_cv_have_proc_uptime = yes; then
    AC_DEFINE(HAVE_PROC_UPTIME, 1,
	      [  Define if your system has the /proc/uptime special file.])
  fi
])

#serial 3

# See if we need to emulate a missing ftruncate function using fcntl or chsize.

AC_DEFUN(jm_FUNC_FTRUNCATE,
[
  AC_CHECK_FUNCS(ftruncate, , [ftruncate_missing=yes])

  if test "$ftruncate_missing" = yes; then
    AC_CHECK_HEADERS([unistd.h])
    AC_CHECK_FUNCS([chsize])
    AC_LIBOBJ(ftruncate)
  fi
])

#serial 2

dnl From Volker Borchert.
dnl Determine whether rename works for source paths with a trailing slash.
dnl The rename from SunOS 4.1.1_U1 doesn't.
dnl
dnl If it doesn't, then define RENAME_TRAILING_SLASH_BUG and arrange
dnl to compile the wrapper function.
dnl

AC_DEFUN(vb_FUNC_RENAME,
[
 AC_CACHE_CHECK([whether rename is broken],
  vb_cv_func_rename_trailing_slash_bug,
  [
    rm -rf conftest.d1 conftest.d2
    mkdir conftest.d1 ||
      AC_MSG_ERROR([cannot create temporary directory])
    AC_TRY_RUN([
#       include <stdio.h>
        int
        main ()
        {
          exit (rename ("conftest.d1/", "conftest.d2") ? 1 : 0);
        }
      ],
      vb_cv_func_rename_trailing_slash_bug=no,
      vb_cv_func_rename_trailing_slash_bug=yes,
      dnl When crosscompiling, assume rename is broken.
      vb_cv_func_rename_trailing_slash_bug=yes)

      rm -rf conftest.d1 conftest.d2
  ])
  if test $vb_cv_func_rename_trailing_slash_bug = yes; then
    AC_LIBOBJ(rename)
    AC_DEFINE_UNQUOTED(RENAME_TRAILING_SLASH_BUG, 1,
[Define if rename does not work for source paths with a trailing slash,
   like the one from SunOS 4.1.1_U1.])
  fi
])

#serial 2

dnl From Jim Meyering
dnl Replace the utime function on systems that need it.

dnl FIXME

AC_DEFUN(jm_FUNC_UTIME,
[
  AC_CHECK_HEADERS(utime.h)
  AC_REQUIRE([jm_CHECK_TYPE_STRUCT_UTIMBUF])
  AC_REQUIRE([AC_FUNC_UTIME_NULL])

  if test $ac_cv_func_utime_null = no; then
    jm_FUNC_UTIMES_NULL
    AC_REPLACE_FUNCS(utime)
  fi
])

#serial 3

dnl Shamelessly cloned from acspecific.m4's AC_FUNC_UTIME_NULL,
dnl then do case-insensitive s/utime/utimes/.

AC_DEFUN(jm_FUNC_UTIMES_NULL,
[AC_CACHE_CHECK(whether utimes accepts a null argument, ac_cv_func_utimes_null,
[rm -f conftest.data; > conftest.data
AC_TRY_RUN([
/* In case stat has been defined to rpl_stat, undef it here.  */
#undef stat
#include <sys/types.h>
#include <sys/stat.h>
main() {
struct stat s, t;
exit(!(stat ("conftest.data", &s) == 0
       && utimes("conftest.data", (long *)0) == 0
       && stat("conftest.data", &t) == 0
       && t.st_mtime >= s.st_mtime
       && t.st_mtime - s.st_mtime < 120));
}],
  ac_cv_func_utimes_null=yes,
  ac_cv_func_utimes_null=no,
  ac_cv_func_utimes_null=no)
rm -f core core.* *.core])

    if test $ac_cv_func_utimes_null = yes; then
      AC_DEFINE_UNQUOTED(HAVE_UTIMES_NULL, 1,
			 [Define if utimes accepts a null argument])
    fi
  ]
)

#serial 4

dnl See if there's a working, system-supplied version of the getline function.
dnl We can't just do AC_REPLACE_FUNCS(getline) because some systems
dnl have a function by that name in -linet that doesn't have anything
dnl to do with the function we need.
AC_DEFUN(AM_FUNC_GETLINE,
[dnl
  am_getline_needs_run_time_check=no
  AC_CHECK_FUNC(getline,
		dnl Found it in some library.  Verify that it works.
		am_getline_needs_run_time_check=yes,
		am_cv_func_working_getline=no)
  if test $am_getline_needs_run_time_check = yes; then
    AC_CHECK_HEADERS(string.h)
    AC_CACHE_CHECK([for working getline function], am_cv_func_working_getline,
    [echo fooN |tr -d '\012'|tr N '\012' > conftest.data
    AC_TRY_RUN([
#    include <stdio.h>
#    include <sys/types.h>
#    if HAVE_STRING_H
#     include <string.h>
#    endif
    int main ()
    { /* Based on a test program from Karl Heuer.  */
      char *line = NULL;
      size_t siz = 0;
      int len;
      FILE *in = fopen ("./conftest.data", "r");
      if (!in)
	return 1;
      len = getline (&line, &siz, in);
      exit ((len == 4 && line && strcmp (line, "foo\n") == 0) ? 0 : 1);
    }
    ], am_cv_func_working_getline=yes dnl The library version works.
    , am_cv_func_working_getline=no dnl The library version does NOT work.
    , am_cv_func_working_getline=no dnl We're cross compiling.
    )])
  fi

  if test $am_cv_func_working_getline = no; then
    AC_LIBOBJ(getline)
  fi
])

# From Jim Meyering.
# FIXME: migrate into libit.

AC_DEFUN([AM_FUNC_OBSTACK],
[AC_CACHE_CHECK([for obstacks], am_cv_func_obstack,
 [AC_TRY_LINK([#include "obstack.h"],
	      [struct obstack *mem;obstack_free(mem,(char *) 0)],
	      am_cv_func_obstack=yes,
	      am_cv_func_obstack=no)])
 if test $am_cv_func_obstack = yes; then
   AC_DEFINE(HAVE_OBSTACK,1,[Define if libc includes obstacks])
 else
   LIBOBJS="$LIBOBJS obstack.$ac_objext"
 fi
])








AC_DEFUN([AM_FUNC_STRTOD],
[AC_CACHE_CHECK(for working strtod, am_cv_func_strtod,
[AC_TRY_RUN([
double strtod ();
int
main()
{
  {
    /* Some versions of Linux strtod mis-parse strings with leading '+'.  */
    char *string = " +69";
    char *term;
    double value;
    value = strtod (string, &term);
    if (value != 69 || term != (string + 4))
      exit (1);
  }

  {
    /* Under Solaris 2.4, strtod returns the wrong value for the
       terminating character under some conditions.  */
    char *string = "NaN";
    char *term;
    strtod (string, &term);
    if (term != string && *(term - 1) == 0)
      exit (1);
  }
  exit (0);
}
], am_cv_func_strtod=yes, am_cv_func_strtod=no, am_cv_func_strtod=no)])
test $am_cv_func_strtod = no && LIBOBJS="$LIBOBJS strtod.$ac_objext"
AC_SUBST(LIBOBJS)dnl
am_cv_func_strtod_needs_libm=no
if test $am_cv_func_strtod = no; then
  AC_CHECK_FUNCS(pow)
  if test $ac_cv_func_pow = no; then
    AC_CHECK_LIB(m, pow, [am_cv_func_strtod_needs_libm=yes],
		 [AC_MSG_WARN([can't find library containing definition of pow])])
  fi
fi
])

#serial 2

dnl From Bruno Haible.

AC_DEFUN(jm_LANGINFO_CODESET,
[
  AC_CHECK_HEADERS(langinfo.h)
  AC_CHECK_FUNCS(nl_langinfo)

  AC_CACHE_CHECK([for nl_langinfo and CODESET], jm_cv_langinfo_codeset,
    [AC_TRY_LINK([#include <langinfo.h>],
      [char* cs = nl_langinfo(CODESET);],
      jm_cv_langinfo_codeset=yes,
      jm_cv_langinfo_codeset=no)
    ])
  if test $jm_cv_langinfo_codeset = yes; then
    AC_DEFINE(HAVE_LANGINFO_CODESET, 1,
      [Define if you have <langinfo.h> and nl_langinfo(CODESET).])
  fi
])

#serial 2

# Test for the GNU C Library, version 2.1 or newer.
# From Bruno Haible.

AC_DEFUN(jm_GLIBC21,
  [
    AC_CACHE_CHECK(whether we are using the GNU C Library 2.1 or newer,
      ac_cv_gnu_library_2_1,
      [AC_EGREP_CPP([Lucky GNU user],
	[
#include <features.h>
#ifdef __GNU_LIBRARY__
 #if (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1) || (__GLIBC__ > 2)
  Lucky GNU user
 #endif
#endif
	],
	ac_cv_gnu_library_2_1=yes,
	ac_cv_gnu_library_2_1=no)
      ]
    )
    AC_SUBST(GLIBC21)
    GLIBC21="$ac_cv_gnu_library_2_1"
  ]
)

#serial 3

dnl From Bruno Haible.

AC_DEFUN(jm_ICONV,
[
  dnl Some systems have iconv in libc, some have it in libiconv (OSF/1 and
  dnl those with the standalone portable GNU libiconv installed).
  AC_CACHE_CHECK(for iconv, jm_cv_func_iconv, [
    jm_cv_func_iconv="no, consider installing GNU libiconv"
    jm_cv_lib_iconv=no
    AC_TRY_LINK([#include <stdlib.h>
#include <iconv.h>],
      [iconv_t cd = iconv_open("","");
       iconv(cd,NULL,NULL,NULL,NULL);
       iconv_close(cd);],
      jm_cv_func_iconv=yes)
    if test "$jm_cv_func_iconv" != yes; then
      jm_save_LIBS="$LIBS"
      LIBS="$LIBS -liconv"
      AC_TRY_LINK([#include <stdlib.h>
#include <iconv.h>],
        [iconv_t cd = iconv_open("","");
         iconv(cd,NULL,NULL,NULL,NULL);
         iconv_close(cd);],
        jm_cv_lib_iconv=yes
        jm_cv_func_iconv=yes)
      LIBS="$jm_save_LIBS"
    fi
  ])
  if test "$jm_cv_func_iconv" = yes; then
    AC_DEFINE(HAVE_ICONV, 1, [Define if you have the iconv() function.])
    AC_MSG_CHECKING([for iconv declaration])
    AC_CACHE_VAL(jm_cv_proto_iconv, [
      AC_TRY_COMPILE([
#include <stdlib.h>
#include <iconv.h>
extern
#ifdef __cplusplus
"C"
#endif
#if defined(__STDC__) || defined(__cplusplus)
size_t iconv (iconv_t cd, char * *inbuf, size_t *inbytesleft, char * *outbuf, size_t* outbytesleft);
#else
size_t iconv();
#endif
], [], jm_cv_proto_iconv_arg1="", jm_cv_proto_iconv_arg1="const")
      jm_cv_proto_iconv="extern size_t iconv (iconv_t cd, $jm_cv_proto_iconv_arg1 char * *inbuf, size_t *inbytesleft, char * *outbuf, size_t* outbytesleft);"])
    jm_cv_proto_iconv=`echo "[$]jm_cv_proto_iconv" | tr -s ' ' | sed -e 's/( /(/'`
    AC_MSG_RESULT([$]{ac_t:-
         }[$]jm_cv_proto_iconv)
    AC_DEFINE_UNQUOTED(ICONV_CONST, $jm_cv_proto_iconv_arg1,
      [Define as const if the declaration of iconv() needs const.])
  fi
  LIBICONV=
  if test "$jm_cv_lib_iconv" = yes; then
    LIBICONV="-liconv"
  fi
  AC_SUBST(LIBICONV)
])

#serial 5

dnl From J. David Anglin.

dnl HPUX and other systems can't unlink shared text that is being executed.

AC_DEFUN(jm_FUNC_UNLINK_BUSY_TEXT,
[dnl
  AC_CACHE_CHECK([whether a running program can be unlinked],
    jm_cv_func_unlink_busy_text,
    [
      AC_TRY_RUN([
        main (argc, argv)
          int argc;
          char **argv;
        {
          if (!argc)
            exit (-1);
          exit (unlink (argv[0]));
        }
	],
      jm_cv_func_unlink_busy_text=yes,
      jm_cv_func_unlink_busy_text=no,
      jm_cv_func_unlink_busy_text=no
      )
    ]
  )

  if test $jm_cv_func_unlink_busy_text = no; then
    INSTALL=$ac_install_sh
  fi
])

#serial 10

dnl From Jim Meyering.
dnl
dnl This is not pretty.  I've just taken the autoconf code and wrapped
dnl it in an AC_DEFUN.
dnl

# jm_LIST_MOUNTED_FILESYSTEMS([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
AC_DEFUN(jm_LIST_MOUNTED_FILESYSTEMS,
  [
AC_CHECK_FUNCS(listmntent getmntinfo)
AC_CHECK_HEADERS(mntent.h)

# Determine how to get the list of mounted filesystems.
ac_list_mounted_fs=

# If the getmntent function is available but not in the standard library,
# make sure LIBS contains -lsun (on Irix4) or -lseq (on PTX).
AC_FUNC_GETMNTENT

# This test must precede the ones for getmntent because Unicos-9 is
# reported to have the getmntent function, but its support is incompatible
# with other getmntent implementations.

# NOTE: Normally, I wouldn't use a check for system type as I've done for
# `CRAY' below since that goes against the whole autoconf philosophy.  But
# I think there is too great a chance that some non-Cray system has a
# function named listmntent to risk the false positive.

if test -z "$ac_list_mounted_fs"; then
  # Cray UNICOS 9
  AC_MSG_CHECKING([for listmntent of Cray/Unicos-9])
  AC_CACHE_VAL(fu_cv_sys_mounted_cray_listmntent,
    [fu_cv_sys_mounted_cray_listmntent=no
      AC_EGREP_CPP(yes,
        [#ifdef _CRAY
yes
#endif
        ], [test $ac_cv_func_listmntent = yes \
	    && fu_cv_sys_mounted_cray_listmntent=yes]
      )
    ]
  )
  AC_MSG_RESULT($fu_cv_sys_mounted_cray_listmntent)
  if test $fu_cv_sys_mounted_cray_listmntent = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_LISTMNTENT, 1,
      [Define if there is a function named listmntent that can be used to
   list all mounted filesystems. (UNICOS)])
  fi
fi

if test $ac_cv_func_getmntent = yes; then

  # This system has the getmntent function.
  # Determine whether it's the one-argument variant or the two-argument one.

  if test -z "$ac_list_mounted_fs"; then
    # 4.3BSD, SunOS, HP-UX, Dynix, Irix
    AC_MSG_CHECKING([for one-argument getmntent function])
    AC_CACHE_VAL(fu_cv_sys_mounted_getmntent1,
		 [test $ac_cv_header_mntent_h = yes \
		   && fu_cv_sys_mounted_getmntent1=yes \
		   || fu_cv_sys_mounted_getmntent1=no])
    AC_MSG_RESULT($fu_cv_sys_mounted_getmntent1)
    if test $fu_cv_sys_mounted_getmntent1 = yes; then
      ac_list_mounted_fs=found
      AC_DEFINE(MOUNTED_GETMNTENT1, 1,
  [Define if there is a function named getmntent for reading the list
   of mounted filesystems, and that function takes a single argument.
   (4.3BSD, SunOS, HP-UX, Dynix, Irix)])
    fi
  fi

  if test -z "$ac_list_mounted_fs"; then
    # SVR4
    AC_MSG_CHECKING([for two-argument getmntent function])
    AC_CACHE_VAL(fu_cv_sys_mounted_getmntent2,
    [AC_EGREP_HEADER(getmntent, sys/mnttab.h,
      fu_cv_sys_mounted_getmntent2=yes,
      fu_cv_sys_mounted_getmntent2=no)])
    AC_MSG_RESULT($fu_cv_sys_mounted_getmntent2)
    if test $fu_cv_sys_mounted_getmntent2 = yes; then
      ac_list_mounted_fs=found
      AC_DEFINE(MOUNTED_GETMNTENT2, 1,
  [Define if there is a function named getmntent for reading the list of
   mounted filesystems, and that function takes two arguments.  (SVR4)])
    fi
  fi

  if test -z "$ac_list_mounted_fs"; then
    AC_MSG_ERROR([could not determine how to read list of mounted filesystems])
  fi

fi

if test -z "$ac_list_mounted_fs"; then
  # DEC Alpha running OSF/1.
  AC_MSG_CHECKING([for getfsstat function])
  AC_CACHE_VAL(fu_cv_sys_mounted_getsstat,
  [AC_TRY_LINK([
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/fs_types.h>],
  [struct statfs *stats;
  int numsys = getfsstat ((struct statfs *)0, 0L, MNT_WAIT); ],
    fu_cv_sys_mounted_getsstat=yes,
    fu_cv_sys_mounted_getsstat=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_getsstat)
  if test $fu_cv_sys_mounted_getsstat = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_GETFSSTAT, 1,
	      [Define if there is a function named getfsstat for reading the
   list of mounted filesystems.  (DEC Alpha running OSF/1)])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  # AIX.
  AC_MSG_CHECKING([for mntctl function and struct vmount])
  AC_CACHE_VAL(fu_cv_sys_mounted_vmount,
  [AC_TRY_CPP([#include <fshelp.h>],
    fu_cv_sys_mounted_vmount=yes,
    fu_cv_sys_mounted_vmount=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_vmount)
  if test $fu_cv_sys_mounted_vmount = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_VMOUNT, 1,
	[Define if there is a function named mntctl that can be used to read
   the list of mounted filesystems, and there is a system header file
   that declares `struct vmount.'  (AIX)])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  # SVR3
  AC_MSG_CHECKING([for FIXME existence of three headers])
  AC_CACHE_VAL(fu_cv_sys_mounted_fread_fstyp,
    [AC_TRY_CPP([
#include <sys/statfs.h>
#include <sys/fstyp.h>
#include <mnttab.h>],
		fu_cv_sys_mounted_fread_fstyp=yes,
		fu_cv_sys_mounted_fread_fstyp=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_fread_fstyp)
  if test $fu_cv_sys_mounted_fread_fstyp = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_FREAD_FSTYP, 1,
[Define if (like SVR2) there is no specific function for reading the
   list of mounted filesystems, and your system has these header files:
   <sys/fstyp.h> and <sys/statfs.h>.  (SVR3)])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  # 4.4BSD and DEC OSF/1.
  AC_MSG_CHECKING([for getmntinfo function])
  AC_CACHE_VAL(fu_cv_sys_mounted_getmntinfo,
    [
      ok=
      if test $ac_cv_func_getmntinfo = yes; then
	AC_EGREP_HEADER(f_type;, sys/mount.h,
			ok=yes)
      fi
      test -n "$ok" \
	  && fu_cv_sys_mounted_getmntinfo=yes \
	  || fu_cv_sys_mounted_getmntinfo=no
    ])
  AC_MSG_RESULT($fu_cv_sys_mounted_getmntinfo)
  if test $fu_cv_sys_mounted_getmntinfo = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_GETMNTINFO, 1,
	      [Define if there is a function named getmntinfo for reading the
   list of mounted filesystems.  (4.4BSD)])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  # Ultrix
  AC_MSG_CHECKING([for getmnt function])
  AC_CACHE_VAL(fu_cv_sys_mounted_getmnt,
    [AC_TRY_CPP([
#include <sys/fs_types.h>
#include <sys/mount.h>],
		fu_cv_sys_mounted_getmnt=yes,
		fu_cv_sys_mounted_getmnt=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_getmnt)
  if test $fu_cv_sys_mounted_getmnt = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_GETMNT, 1,
      [Define if there is a function named getmnt for reading the list of
   mounted filesystems.  (Ultrix)])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  # BeOS
  AC_CHECK_FUNCS(next_dev fs_stat_dev)
  AC_CHECK_HEADERS(fs_info.h)
  AC_MSG_CHECKING([for BEOS mounted file system support functions])
  if test $ac_cv_header_fs_info_h = yes \
      && test $ac_cv_func_next_dev = yes \
	&& test $ac_cv_func_fs_stat_dev = yes; then
    fu_result=yes
  else
    fu_result=no
  fi
  AC_MSG_RESULT($fu_result)
  if test $fu_result = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_FS_STAT_DEV, 1,
      [Define if there are functions named next_dev and fs_stat_dev for
   reading the list of mounted filesystems.  (BeOS)])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  # SVR2
  AC_MSG_CHECKING([whether it is possible to resort to fread on /etc/mnttab])
  AC_CACHE_VAL(fu_cv_sys_mounted_fread,
    [AC_TRY_CPP([#include <mnttab.h>],
		fu_cv_sys_mounted_fread=yes,
		fu_cv_sys_mounted_fread=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_fread)
  if test $fu_cv_sys_mounted_fread = yes; then
    ac_list_mounted_fs=found
    AC_DEFINE(MOUNTED_FREAD, 1,
	      [Define if there is no specific function for reading the list of
   mounted filesystems.  fread will be used to read /etc/mnttab.  (SVR2) ])
  fi
fi

if test -z "$ac_list_mounted_fs"; then
  AC_MSG_ERROR([could not determine how to read list of mounted filesystems])
  # FIXME -- no need to abort building the whole package
  # Can't build mountlist.c or anything that needs its functions
fi

AS_IF([test $ac_list_mounted_fs = found], [$1], [$2])

  ])

#serial 2

dnl From Jim Meyering.
dnl
dnl See if struct statfs has the f_fstypename member.
dnl If so, define HAVE_F_FSTYPENAME_IN_STATFS.
dnl

AC_DEFUN(jm_FSTYPENAME,
  [
    AC_CACHE_CHECK([for f_fstypename in struct statfs],
		   fu_cv_sys_f_fstypename_in_statfs,
      [
	AC_TRY_COMPILE(
	  [
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mount.h>
	  ],
	  [struct statfs s; int i = sizeof s.f_fstypename;],
	  fu_cv_sys_f_fstypename_in_statfs=yes,
	  fu_cv_sys_f_fstypename_in_statfs=no
	)
      ]
    )

    if test $fu_cv_sys_f_fstypename_in_statfs = yes; then
      AC_DEFINE_UNQUOTED(HAVE_F_FSTYPENAME_IN_STATFS, 1,
			 [Define if struct statfs has the f_fstypename member.])
    fi
  ]
)

#serial 7

# From fileutils/configure.in

# Try to determine how a program can obtain filesystem usage information.
# If successful, define the appropriate symbol (see fsusage.c) and
# execute ACTION-IF-FOUND.  Otherwise, execute ACTION-IF-NOT-FOUND.
#
# jm_FILE_SYSTEM_USAGE([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])

AC_DEFUN(jm_FILE_SYSTEM_USAGE,
[

echo "checking how to get filesystem space usage..."
ac_fsusage_space=no

# Perform only the link test since it seems there are no variants of the
# statvfs function.  This check is more than just AC_CHECK_FUNCS(statvfs)
# because that got a false positive on SCO OSR5.  Adding the declaration
# of a `struct statvfs' causes this test to fail (as it should) on such
# systems.  That system is reported to work fine with STAT_STATFS4 which
# is what it gets when this test fails.
if test $ac_fsusage_space = no; then
  # SVR4
  AC_CACHE_CHECK([for statvfs function (SVR4)], fu_cv_sys_stat_statvfs,
		 [AC_TRY_LINK([#include <sys/types.h>
#include <sys/statvfs.h>],
			      [struct statvfs fsd; statvfs (0, &fsd);],
			      fu_cv_sys_stat_statvfs=yes,
			      fu_cv_sys_stat_statvfs=no)])
  if test $fu_cv_sys_stat_statvfs = yes; then
    ac_fsusage_space=yes
    AC_DEFINE(STAT_STATVFS, 1,
	      [  Define if there is a function named statvfs.  (SVR4)])
  fi
fi

if test $ac_fsusage_space = no; then
  # DEC Alpha running OSF/1
  AC_MSG_CHECKING([for 3-argument statfs function (DEC OSF/1)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs3_osf1,
  [AC_TRY_RUN([
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mount.h>
  main ()
  {
    struct statfs fsd;
    fsd.f_fsize = 0;
    exit (statfs (".", &fsd, sizeof (struct statfs)));
  }],
  fu_cv_sys_stat_statfs3_osf1=yes,
  fu_cv_sys_stat_statfs3_osf1=no,
  fu_cv_sys_stat_statfs3_osf1=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs3_osf1)
  if test $fu_cv_sys_stat_statfs3_osf1 = yes; then
    ac_fsusage_space=yes
    AC_DEFINE(STAT_STATFS3_OSF1, 1,
	      [   Define if  statfs takes 3 args.  (DEC Alpha running OSF/1)])
  fi
fi

if test $ac_fsusage_space = no; then
# AIX
  AC_MSG_CHECKING([for two-argument statfs with statfs.bsize dnl
member (AIX, 4.3BSD)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs2_bsize,
  [AC_TRY_RUN([
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
  main ()
  {
  struct statfs fsd;
  fsd.f_bsize = 0;
  exit (statfs (".", &fsd));
  }],
  fu_cv_sys_stat_statfs2_bsize=yes,
  fu_cv_sys_stat_statfs2_bsize=no,
  fu_cv_sys_stat_statfs2_bsize=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs2_bsize)
  if test $fu_cv_sys_stat_statfs2_bsize = yes; then
    ac_fsusage_space=yes
    AC_DEFINE(STAT_STATFS2_BSIZE, 1,
[  Define if statfs takes 2 args and struct statfs has a field named f_bsize.
   (4.3BSD, SunOS 4, HP-UX, AIX PS/2)])
  fi
fi

if test $ac_fsusage_space = no; then
# SVR3
  AC_MSG_CHECKING([for four-argument statfs (AIX-3.2.5, SVR3)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs4,
  [AC_TRY_RUN([#include <sys/types.h>
#include <sys/statfs.h>
  main ()
  {
  struct statfs fsd;
  exit (statfs (".", &fsd, sizeof fsd, 0));
  }],
    fu_cv_sys_stat_statfs4=yes,
    fu_cv_sys_stat_statfs4=no,
    fu_cv_sys_stat_statfs4=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs4)
  if test $fu_cv_sys_stat_statfs4 = yes; then
    ac_fsusage_space=yes
    AC_DEFINE(STAT_STATFS4, 1,
	      [  Define if statfs takes 4 args.  (SVR3, Dynix, Irix, Dolphin)])
  fi
fi

if test $ac_fsusage_space = no; then
# 4.4BSD and NetBSD
  AC_MSG_CHECKING([for two-argument statfs with statfs.fsize dnl
member (4.4BSD and NetBSD)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs2_fsize,
  [AC_TRY_RUN([#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
  main ()
  {
  struct statfs fsd;
  fsd.f_fsize = 0;
  exit (statfs (".", &fsd));
  }],
  fu_cv_sys_stat_statfs2_fsize=yes,
  fu_cv_sys_stat_statfs2_fsize=no,
  fu_cv_sys_stat_statfs2_fsize=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs2_fsize)
  if test $fu_cv_sys_stat_statfs2_fsize = yes; then
    ac_fsusage_space=yes
    AC_DEFINE(STAT_STATFS2_FSIZE, 1,
[  Define if statfs takes 2 args and struct statfs has a field named f_fsize.
   (4.4BSD, NetBSD)])
  fi
fi

if test $ac_fsusage_space = no; then
  # Ultrix
  AC_MSG_CHECKING([for two-argument statfs with struct fs_data (Ultrix)])
  AC_CACHE_VAL(fu_cv_sys_stat_fs_data,
  [AC_TRY_RUN([#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_FS_TYPES_H
#include <sys/fs_types.h>
#endif
  main ()
  {
  struct fs_data fsd;
  /* Ultrix's statfs returns 1 for success,
     0 for not mounted, -1 for failure.  */
  exit (statfs (".", &fsd) != 1);
  }],
  fu_cv_sys_stat_fs_data=yes,
  fu_cv_sys_stat_fs_data=no,
  fu_cv_sys_stat_fs_data=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_fs_data)
  if test $fu_cv_sys_stat_fs_data = yes; then
    ac_fsusage_space=yes
    AC_DEFINE(STAT_STATFS2_FS_DATA, 1,
[  Define if statfs takes 2 args and the second argument has
   type struct fs_data.  (Ultrix)])
  fi
fi

if test $ac_fsusage_space = no; then
  # SVR2
  AC_TRY_CPP([#include <sys/filsys.h>
    ],
    AC_DEFINE(STAT_READ_FILSYS, 1,
      [Define if there is no specific function for reading filesystems usage
       information and you have the <sys/filsys.h> header file.  (SVR2)])
    ac_fsusage_space=yes)
fi

AS_IF([test $ac_fsusage_space = yes], [$1], [$2])

])

# serial 3

# Define some macros required for proper operation of code in lib/*.c
# on MSDOS/Windows systems.

# From Jim Meyering.

AC_DEFUN(jm_AC_DOS,
  [
    # FIXME: this is incomplete.  Add a compile-test that does something
    # like this:
    #if defined _WIN32 || defined __WIN32__ || defined __MSDOS__

    AH_VERBATIM(FILESYSTEM_PREFIX_LEN,
    [#if FILESYSTEM_ACCEPTS_DRIVE_LETTER_PREFIX
# define FILESYSTEM_PREFIX_LEN(Filename) \
  ((Filename)[0] && (Filename)[1] == ':' ? 2 : 0)
else
# define FILESYSTEM_PREFIX_LEN(Filename) 0
#endif])

    ac_fs_accepts_drive_letter_prefix=0
    AC_DEFINE_UNQUOTED([FILESYSTEM_ACCEPTS_DRIVE_LETTER_PREFIX],
      $ac_fs_accepts_drive_letter_prefix,
      [Define on systems for which file names may have a so-called
       `drive letter' prefix, define this to compute the length of that
       prefix, including the colon.])

    AH_VERBATIM(ISSLASH,
    [#if FILESYSTEM_BACKSLASH_IS_FILE_NAME_SEPARATOR
# define ISSLASH(C) ((C) == '/' || (C) == '\\')
#else
# define ISSLASH(C) ((C) == '/')
#endif])

    ac_fs_backslash_is_file_name_separator=0
    AC_DEFINE_UNQUOTED([FILESYSTEM_BACKSLASH_IS_FILE_NAME_SEPARATOR],
      $ac_fs_backslash_is_file_name_separator,
      [Define if the backslash character may also serve as a file name
       component separator.])
  ])

#serial 2
# Make sure _GNU_SOURCE is defined where necessary: as early as possible
# for configure-time tests, as well as for every source file that includes
# config.h.

# From Jim Meyering.

AC_DEFUN(AC__GNU_SOURCE,
[
  # Make sure that _GNU_SOURCE is defined for all subsequent
  # configure-time compile tests.
  # This definition must be emitted (into confdefs.h) before any
  # test that involves compilation.
  cat >>confdefs.h <<\EOF
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
EOF

  # Emit this code into config.h.in.
  # The ifndef is to avoid redefinition warnings.
  AH_VERBATIM([_GNU_SOURCE], [#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif])
])

#serial 4

dnl From Paul Eggert.

# Define ST_MTIM_NSEC to be the nanoseconds member of struct stat's st_mtim,
# if it exists.

AC_DEFUN(AC_STRUCT_ST_MTIM_NSEC,
 [AC_CACHE_CHECK([for nanoseconds member of struct stat.st_mtim],
   ac_cv_struct_st_mtim_nsec,
   [ac_save_CPPFLAGS="$CPPFLAGS"
    ac_cv_struct_st_mtim_nsec=no
    # tv_nsec -- the usual case
    # _tv_nsec -- Solaris 2.6, if
    #	(defined _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED == 1
    #	 && !defined __EXTENSIONS__)
    # st__tim.tv_nsec -- UnixWare 2.1.2
    for ac_val in tv_nsec _tv_nsec st__tim.tv_nsec; do
      CPPFLAGS="$ac_save_CPPFLAGS -DST_MTIM_NSEC=$ac_val"
      AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>], [struct stat s; s.st_mtim.ST_MTIM_NSEC;],
        [ac_cv_struct_st_mtim_nsec=$ac_val; break])
    done
    CPPFLAGS="$ac_save_CPPFLAGS"])

  if test $ac_cv_struct_st_mtim_nsec != no; then
    AC_DEFINE_UNQUOTED(ST_MTIM_NSEC, $ac_cv_struct_st_mtim_nsec,
      [Define to be the nanoseconds member of struct stat's st_mtim,
   if it exists.])
  fi
 ]
)

#serial 2

# Define HAVE_ST_DM_MODE if struct stat has an st_dm_mode member.

AC_DEFUN(AC_STRUCT_ST_DM_MODE,
 [AC_CACHE_CHECK([for st_dm_mode in struct stat], ac_cv_struct_st_dm_mode,
   [AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>], [struct stat s; s.st_dm_mode;],
     ac_cv_struct_st_dm_mode=yes,
     ac_cv_struct_st_dm_mode=no)])

  if test $ac_cv_struct_st_dm_mode = yes; then
    AC_DEFINE_UNQUOTED(HAVE_ST_DM_MODE, 1,
		       [Define if struct stat has an st_dm_mode member. ])
  fi
 ]
)

#serial 4

dnl From Jim Meyering

dnl Define HAVE_STRUCT_TIMESPEC if `struct timespec' is declared
dnl in time.h or sys/time.h.

AC_DEFUN(jm_CHECK_TYPE_STRUCT_TIMESPEC,
[
  AC_REQUIRE([AC_HEADER_TIME])
  AC_CACHE_CHECK([for struct timespec], fu_cv_sys_struct_timespec,
    [AC_TRY_COMPILE(
      [
#      if TIME_WITH_SYS_TIME
#       include <sys/time.h>
#       include <time.h>
#      else
#       if HAVE_SYS_TIME_H
#        include <sys/time.h>
#       else
#        include <time.h>
#       endif
#      endif
      ],
      [static struct timespec x; x.tv_sec = x.tv_nsec;],
      fu_cv_sys_struct_timespec=yes,
      fu_cv_sys_struct_timespec=no)
    ])

  if test $fu_cv_sys_struct_timespec = yes; then
    AC_DEFINE_UNQUOTED(HAVE_STRUCT_TIMESPEC, 1,
		       [Define if struct timespec is declared in <time.h>. ])
  fi
])

# From Jim Meyering.

# serial 1

AC_DEFUN([AM_HEADER_TIOCGWINSZ_NEEDS_SYS_IOCTL],
[AC_REQUIRE([AM_SYS_POSIX_TERMIOS])
 AC_CACHE_CHECK([whether use of TIOCGWINSZ requires sys/ioctl.h],
	        am_cv_sys_tiocgwinsz_needs_sys_ioctl_h,
  [am_cv_sys_tiocgwinsz_needs_sys_ioctl_h=no

  gwinsz_in_termios_h=no
  if test $am_cv_sys_posix_termios = yes; then
    AC_EGREP_CPP([yes],
    [#include <sys/types.h>
#     include <termios.h>
#     ifdef TIOCGWINSZ
        yes
#     endif
    ], gwinsz_in_termios_h=yes)
  fi

  if test $gwinsz_in_termios_h = no; then
    AC_EGREP_CPP([yes],
    [#include <sys/types.h>
#     include <sys/ioctl.h>
#     ifdef TIOCGWINSZ
        yes
#     endif
    ], am_cv_sys_tiocgwinsz_needs_sys_ioctl_h=yes)
  fi
  ])
  if test $am_cv_sys_tiocgwinsz_needs_sys_ioctl_h = yes; then
    AC_DEFINE(GWINSZ_IN_SYS_IOCTL,1,
              [Define if TIOCGWINSZ requires sys/ioctl.h])
  fi
])

# From Jim Meyering.

# serial 1

AC_DEFUN([AM_SYS_POSIX_TERMIOS],
[AC_CACHE_CHECK([POSIX termios], am_cv_sys_posix_termios,
  [AC_TRY_LINK([#include <sys/types.h>
#include <unistd.h>
#include <termios.h>],
  [/* SunOS 4.0.3 has termios.h but not the library calls.  */
   tcgetattr(0, 0);],
  am_cv_sys_posix_termios=yes,
  am_cv_sys_posix_termios=no)])
])

dnl From Jim Meyering.
#serial 3
AC_DEFUN(jm_HEADER_TIOCGWINSZ_IN_TERMIOS_H,
[AC_REQUIRE([AM_SYS_POSIX_TERMIOS])
 AC_CACHE_CHECK([whether use of TIOCGWINSZ requires termios.h],
	        jm_cv_sys_tiocgwinsz_needs_termios_h,
  [jm_cv_sys_tiocgwinsz_needs_termios_h=no

   if test $am_cv_sys_posix_termios = yes; then
     AC_EGREP_CPP([yes],
     [#include <sys/types.h>
#      include <termios.h>
#      ifdef TIOCGWINSZ
         yes
#      endif
     ], jm_cv_sys_tiocgwinsz_needs_termios_h=yes)
   fi
  ])
])

AC_DEFUN(jm_WINSIZE_IN_PTEM,
  [AC_CHECK_HEADER([sys/ptem.h],
		   AC_DEFINE(WINSIZE_IN_PTEM, 1,
      [Define if your system defines `struct winsize' in sys/ptem.h.]))
  ]
)

#serial 4

dnl Misc lib-related macros for fileutils, sh-utils, textutils.

AC_DEFUN(jm_LIB_CHECK,
[

  # Check for libypsec.a on Dolphin M88K machines.
  AC_CHECK_LIB(ypsec, main)

  # m88k running dgux 5.4 needs this
  AC_CHECK_LIB(ldgc, main)

  # Some programs need to link with -lm.  printf does if it uses
  # lib/strtod.c which uses pow.  And seq uses the math functions,
  # floor, modf, rint.  And factor uses sqrt.  And sleep uses fesetround.

  # Save a copy of $LIBS and add $FLOOR_LIBM before these tests
  # Check for these math functions used by seq.
  ac_su_saved_lib="$LIBS"
  LIBS="$LIBS -lm"
  AC_CHECK_FUNCS(floor modf rint)
  LIBS="$ac_su_saved_lib"

  AC_SUBST(SQRT_LIBM)
  AC_CHECK_FUNCS(sqrt)
  if test $ac_cv_func_sqrt = no; then
    AC_CHECK_LIB(m, sqrt, [SQRT_LIBM=-lm])
  fi

  AC_SUBST(FESETROUND_LIBM)
  AC_CHECK_FUNCS(fesetround)
  if test $ac_cv_func_fesetround = no; then
    AC_CHECK_LIB(m, fesetround, [FESETROUND_LIBM=-lm])
  fi

  # The -lsun library is required for YP support on Irix-4.0.5 systems.
  # m88k/svr3 DolphinOS systems using YP need -lypsec for id.
  AC_SEARCH_LIBS(yp_match, [sun ypsec])

  # SysV needs -lsec, older versions of Linux need -lshadow for
  # shadow passwords.  UnixWare 7 needs -lgen.
  AC_SEARCH_LIBS(getspnam, [shadow sec gen])

  AC_CHECK_HEADERS(shadow.h)

  # Requirements for su.c.
  shadow_includes="\
$ac_includes_default
#if HAVE_SHADOW_H
# include <shadow.h>
#endif
"
  AC_CHECK_MEMBERS([struct spwd.sp_pwdp],,,[$shadow_includes])
  AC_CHECK_FUNCS(getspnam)

  # SCO-ODT-3.0 is reported to need -lufc for crypt.
  # NetBSD needs -lcrypt for crypt.
  ac_su_saved_lib="$LIBS"
  AC_SEARCH_LIBS(crypt, [ufc crypt], [LIB_CRYPT="$ac_cv_search_crypt"])
  LIBS="$ac_su_saved_lib"
  AC_SUBST(LIB_CRYPT)
])

# Macro to add for using GNU gettext.
# Ulrich Drepper <drepper@cygnus.com>, 1995.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License
# but which still want to provide support for the GNU gettext functionality.
# Please note that the actual code is *not* freely available.

# serial 110

AC_PREREQ(2.13)               dnl Minimum Autoconf version required.

AC_DEFUN(AM_WITH_NLS,
  [AC_MSG_CHECKING([whether NLS is requested])
    dnl Default is enabled NLS
    AC_ARG_ENABLE(nls,
      [  --disable-nls           do not use Native Language Support],
      USE_NLS=$enableval, USE_NLS=yes)
    AC_MSG_RESULT($USE_NLS)
    AC_SUBST(USE_NLS)

    USE_INCLUDED_LIBINTL=no

    dnl If we use NLS figure out what method
    if test "$USE_NLS" = "yes"; then
      AC_DEFINE(ENABLE_NLS, 1, [Define to 1 if NLS is requested.])
      AC_MSG_CHECKING([whether included gettext is requested])
      AC_ARG_WITH(included-gettext,
        [  --with-included-gettext use the GNU gettext library included here],
        nls_cv_force_use_gnu_gettext=$withval,
        nls_cv_force_use_gnu_gettext=no)
      AC_MSG_RESULT($nls_cv_force_use_gnu_gettext)

      nls_cv_use_gnu_gettext="$nls_cv_force_use_gnu_gettext"
      if test "$nls_cv_force_use_gnu_gettext" != "yes"; then
        dnl User does not insist on using GNU NLS library.  Figure out what
        dnl to use.  If gettext or catgets are available (in this order) we
        dnl use this.  Else we have to fall back to GNU NLS library.
	dnl catgets is only used if permitted by option --with-catgets.
	nls_cv_header_intl=
	nls_cv_header_libgt=
	CATOBJEXT=NONE

	AC_CHECK_HEADER(libintl.h,
	  [AC_CACHE_CHECK([for gettext in libc], gt_cv_func_gettext_libc,
	    [AC_TRY_LINK([#include <libintl.h>], [return (int) gettext ("")],
	       gt_cv_func_gettext_libc=yes, gt_cv_func_gettext_libc=no)])

	   if test "$gt_cv_func_gettext_libc" != "yes"; then
	     AC_CHECK_LIB(intl, bindtextdomain,
	       [AC_CHECK_LIB(intl, gettext)])
	   fi

	   if test "$gt_cv_func_gettext_libc" = "yes" \
	      || test "$ac_cv_lib_intl_gettext" = "yes"; then
	      AC_DEFINE(HAVE_GETTEXT, 1,
	  [Define to 1 if you have gettext and don't want to use GNU gettext.])
	      AM_PATH_PROG_WITH_TEST(MSGFMT, msgfmt,
		[test -z "`$ac_dir/$ac_word -h 2>&1 | grep 'dv '`"], no)dnl
	      if test "$MSGFMT" != "no"; then
		AC_CHECK_FUNCS(dcgettext)
		AC_PATH_PROG(GMSGFMT, gmsgfmt, $MSGFMT)
		AM_PATH_PROG_WITH_TEST(XGETTEXT, xgettext,
		  [test -z "`$ac_dir/$ac_word -h 2>&1 | grep '(HELP)'`"], :)
		AC_TRY_LINK(, [extern int _nl_msg_cat_cntr;
			       return _nl_msg_cat_cntr],
		  [CATOBJEXT=.gmo
		   DATADIRNAME=share],
		  [CATOBJEXT=.mo
		   DATADIRNAME=lib])
		INSTOBJEXT=.mo
	      fi
	    fi
	])

        if test "$CATOBJEXT" = "NONE"; then
	  AC_MSG_CHECKING([whether catgets can be used])
	  AC_ARG_WITH(catgets,
	    [  --with-catgets          use catgets functions if available],
	    nls_cv_use_catgets=$withval, nls_cv_use_catgets=no)
	  AC_MSG_RESULT($nls_cv_use_catgets)

	  if test "$nls_cv_use_catgets" = "yes"; then
	    dnl No gettext in C library.  Try catgets next.
	    AC_CHECK_LIB(i, main)
	    AC_CHECK_FUNC(catgets,
	      [AC_DEFINE(HAVE_CATGETS, 1,
			 [Define as 1 if you have catgets and don't want to use GNU gettext.])
	       INTLOBJS="\$(CATOBJS)"
	       AC_PATH_PROG(GENCAT, gencat, no)dnl
	       if test "$GENCAT" != "no"; then
		 AC_PATH_PROG(GMSGFMT, gmsgfmt, no)
		 if test "$GMSGFMT" = "no"; then
		   AM_PATH_PROG_WITH_TEST(GMSGFMT, msgfmt,
		    [test -z "`$ac_dir/$ac_word -h 2>&1 | grep 'dv '`"], no)
		 fi
		 AM_PATH_PROG_WITH_TEST(XGETTEXT, xgettext,
		   [test -z "`$ac_dir/$ac_word -h 2>&1 | grep '(HELP)'`"], :)
		 USE_INCLUDED_LIBINTL=yes
		 CATOBJEXT=.cat
		 INSTOBJEXT=.cat
		 DATADIRNAME=lib
		 INTLDEPS='$(top_builddir)/intl/libintl.a'
		 INTLLIBS=$INTLDEPS
		 LIBS=`echo $LIBS | sed -e 's/-lintl//'`
		 nls_cv_header_intl=intl/libintl.h
		 nls_cv_header_libgt=intl/libgettext.h
	       fi])
	  fi
        fi

        if test "$CATOBJEXT" = "NONE"; then
	  dnl Neither gettext nor catgets in included in the C library.
	  dnl Fall back on GNU gettext library.
	  nls_cv_use_gnu_gettext=yes
        fi
      fi

      if test "$nls_cv_use_gnu_gettext" = "yes"; then
        dnl Mark actions used to generate GNU NLS library.
        INTLOBJS="\$(GETTOBJS)"
        AM_PATH_PROG_WITH_TEST(MSGFMT, msgfmt,
	  [test -z "`$ac_dir/$ac_word -h 2>&1 | grep 'dv '`"], msgfmt)
        AC_PATH_PROG(GMSGFMT, gmsgfmt, $MSGFMT)
        AM_PATH_PROG_WITH_TEST(XGETTEXT, xgettext,
	  [test -z "`$ac_dir/$ac_word -h 2>&1 | grep '(HELP)'`"], :)
        AC_SUBST(MSGFMT)
	USE_INCLUDED_LIBINTL=yes
        CATOBJEXT=.gmo
        INSTOBJEXT=.mo
        DATADIRNAME=share
	INTLDEPS='$(top_builddir)/intl/libintl.a'
	INTLLIBS=$INTLDEPS
	LIBS=`echo $LIBS | sed -e 's/-lintl//'`
        nls_cv_header_intl=intl/libintl.h
        nls_cv_header_libgt=intl/libgettext.h
      fi

      dnl Test whether we really found GNU xgettext.
      if test "$XGETTEXT" != ":"; then
	dnl If it is no GNU xgettext we define it as : so that the
	dnl Makefiles still can work.
	if $XGETTEXT --omit-header /dev/null 2> /dev/null; then
	  : ;
	else
	  AC_MSG_RESULT(
	    [found xgettext program is not GNU xgettext; ignore it])
	  XGETTEXT=":"
	fi
      fi

      # We need to process the po/ directory.
      POSUB=po
    else
      DATADIRNAME=share
      nls_cv_header_intl=intl/libintl.h
      nls_cv_header_libgt=intl/libgettext.h
    fi
    if test -z "$nls_cv_header_intl"; then
      # Clean out junk possibly left behind by a previous configuration.
      rm -f intl/libintl.h
    fi
    AC_CONFIG_LINKS($nls_cv_header_intl:$nls_cv_header_libgt)
    AC_OUTPUT_COMMANDS(
     [case "$CONFIG_FILES" in *po/Makefile.in*)
        sed -e "/POTFILES =/r po/POTFILES" po/Makefile.in > po/Makefile
      esac])


    # If this is used in GNU gettext we have to set USE_NLS to `yes'
    # because some of the sources are only built for this goal.
    if test "$PACKAGE" = gettext; then
      USE_NLS=yes
      USE_INCLUDED_LIBINTL=yes
    fi

    dnl These rules are solely for the distribution goal.  While doing this
    dnl we only have to keep exactly one list of the available catalogs
    dnl in configure.in.
    for lang in $ALL_LINGUAS; do
      GMOFILES="$GMOFILES $lang.gmo"
      POFILES="$POFILES $lang.po"
    done

    dnl Make all variables we use known to autoconf.
    AC_SUBST(USE_INCLUDED_LIBINTL)
    AC_SUBST(CATALOGS)
    AC_SUBST(CATOBJEXT)
    AC_SUBST(DATADIRNAME)
    AC_SUBST(GMOFILES)
    AC_SUBST(INSTOBJEXT)
    AC_SUBST(INTLDEPS)
    AC_SUBST(INTLLIBS)
    AC_SUBST(INTLOBJS)
    AC_SUBST(POFILES)
    AC_SUBST(POSUB)
  ])

AC_DEFUN(AM_GNU_GETTEXT,
  [AC_REQUIRE([AC_PROG_MAKE_SET])dnl
   AC_REQUIRE([AC_PROG_CC])dnl
   AC_REQUIRE([AC_PROG_RANLIB])dnl
   AC_REQUIRE([AC_ISC_POSIX])dnl
   AC_REQUIRE([AC_HEADER_STDC])dnl
   AC_REQUIRE([AC_C_CONST])dnl
   AC_REQUIRE([AC_C_INLINE])dnl
   AC_REQUIRE([AC_TYPE_OFF_T])dnl
   AC_REQUIRE([AC_TYPE_SIZE_T])dnl
   AC_REQUIRE([AC_FUNC_ALLOCA])dnl
   AC_REQUIRE([AC_FUNC_MMAP])dnl

   AC_CHECK_HEADERS([argz.h limits.h locale.h nl_types.h malloc.h string.h \
unistd.h sys/param.h])
   AC_CHECK_FUNCS([getcwd munmap putenv setenv setlocale strchr strcasecmp \
strdup __argz_count __argz_stringify __argz_next])

   if test "${ac_cv_func_stpcpy+set}" != "set"; then
     AC_CHECK_FUNCS(stpcpy)
   fi
   if test "${ac_cv_func_stpcpy}" = "yes"; then
     AC_DEFINE(HAVE_STPCPY, 1, [Define to 1 if you have the stpcpy function.])
   fi

   AM_LC_MESSAGES
   AM_WITH_NLS

   if test "x$CATOBJEXT" != "x"; then
     if test "x$ALL_LINGUAS" = "x"; then
       LINGUAS=
     else
       AC_MSG_CHECKING(for catalogs to be installed)
       NEW_LINGUAS=
       for lang in ${LINGUAS=$ALL_LINGUAS}; do
         case "$ALL_LINGUAS" in
          *$lang*) NEW_LINGUAS="$NEW_LINGUAS $lang" ;;
         esac
       done
       LINGUAS=$NEW_LINGUAS
       AC_MSG_RESULT($LINGUAS)
     fi

     dnl Construct list of names of catalog files to be constructed.
     if test -n "$LINGUAS"; then
       for lang in $LINGUAS; do CATALOGS="$CATALOGS $lang$CATOBJEXT"; done
     fi
   fi

   dnl The reference to <locale.h> in the installed <libintl.h> file
   dnl must be resolved because we cannot expect the users of this
   dnl to define HAVE_LOCALE_H.
   if test $ac_cv_header_locale_h = yes; then
     INCLUDE_LOCALE_H="#include <locale.h>"
   else
     INCLUDE_LOCALE_H="\
/* The system does not provide the header <locale.h>.  Take care yourself.  */"
   fi
   AC_SUBST(INCLUDE_LOCALE_H)

   dnl Determine which catalog format we have (if any is needed)
   dnl For now we know about two different formats:
   dnl   Linux libc-5 and the normal X/Open format
   test -d intl || mkdir intl
   if test "$CATOBJEXT" = ".cat"; then
     AC_CHECK_HEADER(linux/version.h, msgformat=linux, msgformat=xopen)

     dnl Transform the SED scripts while copying because some dumb SEDs
     dnl cannot handle comments.
     sed -e '/^#/d' $srcdir/intl/$msgformat-msg.sed > intl/po2msg.sed
   fi
   dnl po2tbl.sed is always needed.
   sed -e '/^#.*[^\\]$/d' -e '/^#$/d' \
     $srcdir/intl/po2tbl.sed.in > intl/po2tbl.sed

   dnl In the intl/Makefile.in we have a special dependency which makes
   dnl only sense for gettext.  We comment this out for non-gettext
   dnl packages.
   if test "$PACKAGE" = "gettext"; then
     GT_NO="#NO#"
     GT_YES=
   else
     GT_NO=
     GT_YES="#YES#"
   fi
   AC_SUBST(GT_NO)
   AC_SUBST(GT_YES)

   dnl If the AC_CONFIG_AUX_DIR macro for autoconf is used we possibly
   dnl find the mkinstalldirs script in another subdir but ($top_srcdir).
   dnl Try to locate it.
   MKINSTALLDIRS=
   if test -n "$ac_aux_dir"; then
     MKINSTALLDIRS="`CDPATH=:; cd $ac_aux_dir && pwd`/mkinstalldirs"
   fi
   if test -z "$MKINSTALLDIRS"; then
     MKINSTALLDIRS="\$(top_srcdir)/mkinstalldirs"
   fi
   AC_SUBST(MKINSTALLDIRS)

   dnl *** For now the libtool support in intl/Makefile is not for real.
   l=
   AC_SUBST(l)

   dnl Generate list of files to be processed by xgettext which will
   dnl be included in po/Makefile.
   test -d po || mkdir po
   case "$srcdir" in
   .)
     posrcprefix="../" ;;
   /* | [[A-Za-z]]:*)
     posrcprefix="$srcdir/" ;;
   *)
     posrcprefix="../$srcdir/" ;;
   esac
   rm -f po/POTFILES
   sed -e "/^#/d" -e "/^\$/d" -e "s,.*,	$posrcprefix& \\\\," -e "\$s/\(.*\) \\\\/\1/" \
	< $srcdir/po/POTFILES.in > po/POTFILES
  ])

# Search path for a program which passes the given test.
# Ulrich Drepper <drepper@cygnus.com>, 1996.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License
# but which still want to provide support for the GNU gettext functionality.
# Please note that the actual code is *not* freely available.

# serial 1

dnl AM_PATH_PROG_WITH_TEST(VARIABLE, PROG-TO-CHECK-FOR,
dnl   TEST-PERFORMED-ON-FOUND_PROGRAM [, VALUE-IF-NOT-FOUND [, PATH]])
AC_DEFUN(AM_PATH_PROG_WITH_TEST,
[# Extract the first word of "$2", so it can be a program name with args.
set dummy $2; ac_word=[$]2
AC_MSG_CHECKING([for $ac_word])
AC_CACHE_VAL(ac_cv_path_$1,
[case "[$]$1" in
  /*)
  ac_cv_path_$1="[$]$1" # Let the user override the test with a path.
  ;;
  *)
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}:"
  for ac_dir in ifelse([$5], , $PATH, [$5]); do
    test -z "$ac_dir" && ac_dir=.
    if test -f $ac_dir/$ac_word; then
      if [$3]; then
	ac_cv_path_$1="$ac_dir/$ac_word"
	break
      fi
    fi
  done
  IFS="$ac_save_ifs"
dnl If no 4th arg is given, leave the cache variable unset,
dnl so AC_PATH_PROGS will keep looking.
ifelse([$4], , , [  test -z "[$]ac_cv_path_$1" && ac_cv_path_$1="$4"
])dnl
  ;;
esac])dnl
$1="$ac_cv_path_$1"
if test -n "[$]$1"; then
  AC_MSG_RESULT([$]$1)
else
  AC_MSG_RESULT(no)
fi
AC_SUBST($1)dnl
])

# Check whether LC_MESSAGES is available in <locale.h>.
# Ulrich Drepper <drepper@cygnus.com>, 1995.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License
# but which still want to provide support for the GNU gettext functionality.
# Please note that the actual code is *not* freely available.

# serial 2

AC_PREREQ(2.13)               dnl Minimum Autoconf version required.

AC_DEFUN(AM_LC_MESSAGES,
  [if test $ac_cv_header_locale_h = yes; then
    AC_CACHE_CHECK([for LC_MESSAGES], am_cv_val_LC_MESSAGES,
      [AC_TRY_LINK([#include <locale.h>], [return LC_MESSAGES],
       am_cv_val_LC_MESSAGES=yes, am_cv_val_LC_MESSAGES=no)])
    if test $am_cv_val_LC_MESSAGES = yes; then
      AC_DEFINE(HAVE_LC_MESSAGES, 1,
		[Define if your locale.h file contains LC_MESSAGES.])
    fi
  fi])

