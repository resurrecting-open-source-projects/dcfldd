## Process this file with automake to produce Makefile.in -*-Makefile-*-
man_MANS = dcfldd.1

EXTRA_DIST = $(man_MANS) $(HELP2MAN) \
  Makefile.maint GNUmakefile Makefile.summ dcfldd.x
PERL = @PERL@
HELP2MAN = help2man
MAINTAINERCLEANFILES = $(man_MANS)

# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.
