## Process this file with automake to produce Makefile.in -*-Makefile-*-
AUTOMAKE_OPTIONS = ansi2knr

bin_PROGRAMS = dcfldd

dcfldd_SOURCES = dcfldd.c md5.c

datadir = $(prefix)/@DATADIRNAME@
localedir = $(datadir)/locale

noinst_HEADERS = system.h sys2.h md5.h

INCLUDES = -I.. -I$(srcdir) -I$(top_srcdir)/lib -I../intl
DEFS = -DLOCALEDIR=\"$(localedir)\" -DSHAREDIR=\"$(datadir)\" @DEFS@
LDADD = @INTLLIBS@ ../lib/libfetish.a

$(bin_PROGRAMS) $(libexec_PROGRAMS): ../lib/libfetish.a

# Use `ginstall' in the definition of PROGRAMS and in dependencies to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.

transform = s/ginstall/install/; @program_transform_name@

PERL = @PERL@
editpl = sed -e 's,@''PERL''@,$(PERL),g'

