#!/bin/sh

# autogen.sh with clean option
# Copyright 2016 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
# Copyright 2023 David da Silva Polverari <david.polverari@gmail.com>
#
# This file is under BSD-3-Clause license.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the authors nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


# Use clean option
if [ "$1" = "clean" -a ! -e Makefile ]
then
    echo "Vanishing the code"
    rm -rf aclocal.m4 autom4te.cache compile config.guess config.h.in \
           config.sub configure depcomp install-sh Makefile.in missing \
           man/Makefile.in src/Makefile.in
    exit 0
fi

# Do not use clean option
if [ "$1" = "clean" -a -e Makefile ]
then
    echo "I can not clean. Use '$ make distclean'."
    exit 0
fi

env pkg-config --version > /dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "pkg-config is missing. Please install it and run $0 again."
    exit 1
fi

# Do autoreconf
autoreconf -i \
   && { echo " "; \
        echo "Done. You can use the 'clean' option to vanish the source code."; \
        echo "Example of use: $ ./autogen clean"; \
      } \
   || { echo "We have a problem..."; exit 1; }
