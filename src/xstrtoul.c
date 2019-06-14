#if HAVE_CONFIG_H
# include "config.h"
#endif

#if HAVE_DECL_STRTOUL
#define __strtol strtoul
#define __strtol_t unsigned long int
#define __xstrtol xstrtoul
#include "xstrtol.c"
#endif
