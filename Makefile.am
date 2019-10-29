## Process this file with automake to produce Makefile.in -*-Makefile-*-
AUTOMAKE_OPTIONS = gnits 1.2h

SUBDIRS = lib intl src doc man m4 po tests
EXTRA_DIST = Makefile.maint GNUmakefile ChangeLog-1997 \
  .kludge-stamp .prev-version

# Remove this file here (it is created via configure), not from within intl.
DISTCLEANFILES = intl/libintl.h

ACLOCAL_AMFLAGS = -I m4

# Some tests always need root privileges, others need them only sometimes.
check-root:
	cd tests && $(MAKE) $@

distcheck-hook:
	$(MAKE) my-distcheck

# Just prior to distribution, ...
# transform the automake-generated rule that runs `rm -f rm'.
# On some systems, that command would fail with a diagnostic like
# `rm: cannot unlink `rm': Text file busy' when `.' appears so early
# in the shell's search path that running `rm' would run the `rm'
# executable in the current directory.
# Similarly, adjust the clean-binPROGRAMS rule.

rm_subst = \
  s!(rm -f (rm|\$$\(bin_PROGRAMS\)))$$!$$1 > /dev/null 2>&1 || /bin/$$1!
.kludge-stamp: $(srcdir)/src/Makefile.in
	perl -pi -e '$(rm_subst)' $(srcdir)/src/Makefile.in
	touch $@
