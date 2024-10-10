#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

extern char *program_invocation_name;

/* mimics GNU libc error() behavior */
void error(int status, int errnum, const char *format, ...) {
	va_list args;
	va_start(args, format);

	fflush (stdout);
	fprintf(stderr, "%s: ", program_invocation_name);

	vfprintf(stderr, format, args);
	va_end(args);

	if (errnum) {
		fprintf(stderr, ": %s", strerror(errnum));
	}

	fprintf(stderr, "\n");

	if (status) {
		exit(status);
	}
}

