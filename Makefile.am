# configure.ac, was previously configure.in (before 2019)
#
# Copyright ?-2002    Jim Meyering <jim@meyering.net>
# Copyright 2002-2006 Nicholas Harbour <nicholasharbour@yahoo.com>
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

AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = src man

distclean-local:
	rm -rf autom4te.cache
	rm -f aclocal.m4 compile config.* configure depcomp install-sh \
	      Makefile.in missing man/Makefile.in src/Makefile.in
