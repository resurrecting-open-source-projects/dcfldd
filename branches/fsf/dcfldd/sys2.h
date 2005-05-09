#ifndef SYS2_H
#define SYS2_H

#if STAT_MACROS_BROKEN
# undef S_ISBLK
# undef S_ISCHR
# undef S_ISDIR
# undef S_ISDOOR
# undef S_ISFIFO
# undef S_ISLNK
# undef S_ISMPB
# undef S_ISMPC
# undef S_ISNWK
# undef S_ISREG
# undef S_ISSOCK
#endif /* STAT_MACROS_BROKEN.  */

#ifndef S_IFMT
# define S_IFMT 0170000
#endif
#if !defined(S_ISBLK) && defined(S_IFBLK)
# define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif
#if !defined(S_ISCHR) && defined(S_IFCHR)
# define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif
#if !defined(S_ISDIR) && defined(S_IFDIR)
# define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#if !defined(S_ISREG) && defined(S_IFREG)
# define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#if !defined(S_ISFIFO) && defined(S_IFIFO)
# define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#if !defined(S_ISLNK) && defined(S_IFLNK)
# define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#if !defined(S_ISSOCK) && defined(S_IFSOCK)
# define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif
#if !defined(S_ISMPB) && defined(S_IFMPB) /* V7 */
# define S_ISMPB(m) (((m) & S_IFMT) == S_IFMPB)
# define S_ISMPC(m) (((m) & S_IFMT) == S_IFMPC)
#endif
#if !defined(S_ISNWK) && defined(S_IFNWK) /* HP/UX */
# define S_ISNWK(m) (((m) & S_IFMT) == S_IFNWK)
#endif
#if !defined(S_ISDOOR) && defined(S_IFDOOR) /* Solaris 2.5 and up */
# define S_ISDOOR(m) (((m) & S_IFMT) == S_IFDOOR)
#endif

#if !S_ISUID
# define S_ISUID 04000
#endif
#if !S_ISGID
# define S_ISGID 02000
#endif

/* S_ISVTX is a common extension to POSIX.1.  */
#ifndef S_ISVTX
# define S_ISVTX 01000
#endif

#if !S_IRUSR && S_IREAD
# define S_IRUSR S_IREAD
#endif
#if !S_IRUSR
# define S_IRUSR 00400
#endif
#if !S_IRGRP
# define S_IRGRP (S_IRUSR >> 3)
#endif
#if !S_IROTH
# define S_IROTH (S_IRUSR >> 6)
#endif

#if !S_IWUSR && S_IWRITE
# define S_IWUSR S_IWRITE
#endif
#if !S_IWUSR
# define S_IWUSR 00200
#endif
#if !S_IWGRP
# define S_IWGRP (S_IWUSR >> 3)
#endif
#if !S_IWOTH
# define S_IWOTH (S_IWUSR >> 6)
#endif

#if !S_IXUSR && S_IEXEC
# define S_IXUSR S_IEXEC
#endif
#if !S_IXUSR
# define S_IXUSR 00100
#endif
#if !S_IXGRP
# define S_IXGRP (S_IXUSR >> 3)
#endif
#if !S_IXOTH
# define S_IXOTH (S_IXUSR >> 6)
#endif

#if !S_IRWXU
# define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#endif
#if !S_IRWXG
# define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)
#endif
#if !S_IRWXO
# define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#endif

/* S_IXUGO is a common extension to POSIX.1.  */
#if !S_IXUGO
# define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)
#endif

#ifndef S_IRWXUGO
# define S_IRWXUGO (S_IRWXU | S_IRWXG | S_IRWXO)
#endif

/* All the mode bits that can be affected by chmod.  */
#define CHMOD_MODE_BITS \
  (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

#ifdef ST_MTIM_NSEC
# define ST_TIME_CMP_NS(a, b, ns) ((a).ns < (b).ns ? -1 : (a).ns > (b).ns)
#else
# define ST_TIME_CMP_NS(a, b, ns) 0
#endif
#define ST_TIME_CMP(a, b, s, ns) \
  ((a).s < (b).s ? -1 : (a).s > (b).s ? 1 : ST_TIME_CMP_NS(a, b, ns))
#define ATIME_CMP(a, b) ST_TIME_CMP (a, b, st_atime, st_atim.ST_MTIM_NSEC)
#define CTIME_CMP(a, b) ST_TIME_CMP (a, b, st_ctime, st_ctim.ST_MTIM_NSEC)
#define MTIME_CMP(a, b) ST_TIME_CMP (a, b, st_mtime, st_mtim.ST_MTIM_NSEC)

#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif

#ifndef __GNUC__
# if HAVE_ALLOCA_H
#  include <alloca.h>
# else
#  ifdef _AIX
 #  pragma alloca
#  else
#   ifdef _WIN32
#    include <malloc.h>
#    include <io.h>
#   else
#    ifndef alloca
char *alloca ();
#    endif
#   endif
#  endif
# endif
#endif

#ifdef __DJGPP__
  /* We need the declaration of setmode.  */
# include <io.h>
  /* We need the declaration of __djgpp_set_ctrl_c.  */
# include <sys/exceptn.h>
#endif

#if HAVE_STDINT_H
# include <stdint.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h> /* for the definition of UINTMAX_MAX */
#endif

#include <ctype.h>

/* Jim Meyering writes:

   "... Some ctype macros are valid only for character codes that
   isascii says are ASCII (SGI's IRIX-4.0.5 is one such system --when
   using /bin/cc or gcc but without giving an ansi option).  So, all
   ctype uses should be through macros like ISPRINT...  If
   STDC_HEADERS is defined, then autoconf has verified that the ctype
   macros don't need to be guarded with references to isascii. ...
   Defining isascii to 1 should let any compiler worth its salt
   eliminate the && through constant folding."

   Bruno Haible adds:

   "... Furthermore, isupper(c) etc. have an undefined result if c is
   outside the range -1 <= c <= 255. One is tempted to write isupper(c)
   with c being of type `char', but this is wrong if c is an 8-bit
   character >= 128 which gets sign-extended to a negative value.
   The macro ISUPPER protects against this as well."  */

#if STDC_HEADERS || (!defined (isascii) && !HAVE_ISASCII)
# define IN_CTYPE_DOMAIN(c) 1
#else
# define IN_CTYPE_DOMAIN(c) isascii(c)
#endif

#ifdef isblank
# define ISBLANK(c) (IN_CTYPE_DOMAIN (c) && isblank (c))
#else
# define ISBLANK(c) ((c) == ' ' || (c) == '\t')
#endif
#ifdef isgraph
# define ISGRAPH(c) (IN_CTYPE_DOMAIN (c) && isgraph (c))
#else
# define ISGRAPH(c) (IN_CTYPE_DOMAIN (c) && isprint (c) && !isspace (c))
#endif

/* This is defined in <sys/euc.h> on at least Solaris2.6 systems.  */
#undef ISPRINT

#define ISPRINT(c) (IN_CTYPE_DOMAIN (c) && isprint (c))
#define ISALNUM(c) (IN_CTYPE_DOMAIN (c) && isalnum (c))
#define ISALPHA(c) (IN_CTYPE_DOMAIN (c) && isalpha (c))
#define ISCNTRL(c) (IN_CTYPE_DOMAIN (c) && iscntrl (c))
#define ISLOWER(c) (IN_CTYPE_DOMAIN (c) && islower (c))
#define ISPUNCT(c) (IN_CTYPE_DOMAIN (c) && ispunct (c))
#define ISSPACE(c) (IN_CTYPE_DOMAIN (c) && isspace (c))
#define ISUPPER(c) (IN_CTYPE_DOMAIN (c) && isupper (c))
#define ISXDIGIT(c) (IN_CTYPE_DOMAIN (c) && isxdigit (c))
#define ISDIGIT_LOCALE(c) (IN_CTYPE_DOMAIN (c) && isdigit (c))

#if STDC_HEADERS
# define TOLOWER(Ch) tolower (Ch)
# define TOUPPER(Ch) toupper (Ch)
#else
# define TOLOWER(Ch) (ISUPPER (Ch) ? tolower (Ch) : (Ch))
# define TOUPPER(Ch) (ISLOWER (Ch) ? toupper (Ch) : (Ch))
#endif

/* ISDIGIT differs from ISDIGIT_LOCALE, as follows:
   - Its arg may be any int or unsigned int; it need not be an unsigned char.
   - It's guaranteed to evaluate its argument exactly once.
   - It's typically faster.
   Posix 1003.2-1992 section 2.5.2.1 page 50 lines 1556-1558 says that
   only '0' through '9' are digits.  Prefer ISDIGIT to ISDIGIT_LOCALE unless
   it's important to use the locale's definition of `digit' even when the
   host does not conform to Posix.  */
#define ISDIGIT(c) ((unsigned) (c) - '0' <= 9)

#ifndef PARAMS
# if PROTOTYPES
#  define PARAMS(Args) Args
# else
#  define PARAMS(Args) ()
# endif
#endif

/* Take care of NLS matters.  */

#if HAVE_LOCALE_H
# include <locale.h>
#endif
#if !HAVE_SETLOCALE
# define setlocale(Category, Locale) /* empty */
#endif

#if ENABLE_NLS
# include <libintl.h>
# if HAVE_GETTEXT && !HAVE_DCGETTEXT && !defined dcgettext
#  define dcgettext(Domain, Text, Category) Text
# endif
# define _(Text) gettext (Text)
#else
# undef bindtextdomain
# define bindtextdomain(Domain, Directory) /* empty */
# undef textdomain
# define textdomain(Domain) /* empty */
# undef dcgettext
# define dcgettext(Domainname, Text, Category) Text
# define _(Text) Text
#endif
#define N_(Text) Text

#define STREQ(a, b) (strcmp ((a), (b)) == 0)

/* This is needed on some AIX systems.  */
#if !HAVE_DECL_STRTOUL
unsigned long strtoul ();
#endif

/* This is needed on some AIX systems.  */
#if !HAVE_DECL_STRTOULL && HAVE_UNSIGNED_LONG_LONG
unsigned long long strtoull ();
#endif

#if !HAVE_DECL_GETLOGIN
char *getlogin ();
#endif

#if !HAVE_DECL_TTYNAME
char *ttyname ();
#endif

#if !HAVE_DECL_GETEUID
uid_t geteuid ();
#endif

#if !HAVE_DECL_GETPWUID
struct passwd *getpwuid ();
#endif

#if !HAVE_DECL_GETGRGID
struct group *getgrgid ();
#endif

#if !HAVE_DECL_GETUID
uid_t getuid ();
#endif

#include "xalloc.h"

#if ! defined HAVE_MEMPCPY && ! defined mempcpy
/* Be CAREFUL that there are no side effects in N.  */
# define mempcpy(D, S, N) ((void *) ((char *) memcpy (D, S, N) + (N)))
#endif

/* These are wrappers for functions/macros from GNU libc.
   The standard I/O functions are thread-safe.  These *_unlocked ones
   are more efficient but not thread-safe.  That they're not thread-safe
   is fine since all these applications are single threaded.  */

#if HAVE_CLEARERR_UNLOCKED
# undef clearerr
# define clearerr(S) clearerr_unlocked (S)
#endif

#if HAVE_FEOF_UNLOCKED
# undef feof
# define feof(S) feof_unlocked (S)
#endif

#if HAVE_FERROR_UNLOCKED
# undef ferror
# define ferror(S) ferror_unlocked (S)
#endif

#if HAVE_FFLUSH_UNLOCKED
# undef fflush
# define fflush(S) fflush_unlocked (S)
#endif

#if HAVE_FPUTC_UNLOCKED
# undef fputc
# define fputc(C, S) fputc_unlocked (C, S)
#endif

#if HAVE_FREAD_UNLOCKED
# undef fread
# define fread(P, Z, N, S) fread_unlocked (P, Z, N, S)
#endif

#if HAVE_FWRITE_UNLOCKED
# undef fwrite
# define fwrite(P, Z, N, S) fwrite_unlocked (P, Z, N, S)
#endif

#if HAVE_GETC_UNLOCKED
# undef getc
# define getc(S) getc_unlocked (S)
#endif

#if HAVE_GETCHAR_UNLOCKED
# undef getchar
# define getchar(S) getchar_unlocked (S)
#endif

#if HAVE_PUTC_UNLOCKED
# undef putc
# define putc(C, S) putc_unlocked (C, S)
#endif

#if HAVE_PUTCHAR_UNLOCKED
# undef putchar
# define putchar(C) putchar_unlocked (C)
#endif

#define SAME_INODE(Stat_buf_1, Stat_buf_2) \
  ((Stat_buf_1).st_ino == (Stat_buf_2).st_ino \
   && (Stat_buf_1).st_dev == (Stat_buf_2).st_dev)

#define DOT_OR_DOTDOT(Basename) \
  (Basename[0] == '.' && (Basename[1] == '\0' \
			  || (Basename[1] == '.' && Basename[2] == '\0')))

#if SETVBUF_REVERSED
# define SETVBUF(Stream, Buffer, Type, Size) \
    setvbuf (Stream, Type, Buffer, Size)
#else
# define SETVBUF(Stream, Buffer, Type, Size) \
    setvbuf (Stream, Buffer, Type, Size)
#endif

char *base_name PARAMS ((char const *));

/* Factor out some of the common --help and --version processing code.  */

/* These enum values cannot possibly conflict with the option values
   ordinarily used by commands, including CHAR_MAX + 1, etc.  Avoid
   CHAR_MIN - 1, as it may equal -1, the getopt end-of-options value.  */
enum
{
  GETOPT_HELP_CHAR = (CHAR_MIN - 2),
  GETOPT_VERSION_CHAR = (CHAR_MIN - 3)
};

#define GETOPT_HELP_OPTION_DECL \
  "help", no_argument, 0, GETOPT_HELP_CHAR
#define GETOPT_VERSION_OPTION_DECL \
  "version", no_argument, 0, GETOPT_VERSION_CHAR

#define case_GETOPT_HELP_CHAR			\
  case GETOPT_HELP_CHAR:			\
    usage (EXIT_SUCCESS);			\
    break;

#include "version-etc.h"

#define case_GETOPT_VERSION_CHAR(Program_name, Authors)			\
  case GETOPT_VERSION_CHAR:						\
    version_etc (stdout, Program_name, PACKAGE, VERSION, Authors);	\
    exit (EXIT_SUCCESS);						\
    break;

#ifndef MAX
# define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
# define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef CHAR_BIT
# define CHAR_BIT 8
#endif

/* The extra casts work around common compiler bugs.  */
#define TYPE_SIGNED(t) (! ((t) 0 < (t) -1))
/* The outer cast is needed to work around a bug in Cray C 5.0.3.0.
   It is necessary at least when t == time_t.  */
#define TYPE_MINIMUM(t) ((t) (TYPE_SIGNED (t) \
			      ? ~ (t) 0 << (sizeof (t) * CHAR_BIT - 1) : (t) 0))
#define TYPE_MAXIMUM(t) ((t) (~ (t) 0 - TYPE_MINIMUM (t)))

/* Upper bound on the string length of an integer converted to string.
   302 / 1000 is ceil (log10 (2.0)).  Subtract 1 for the sign bit;
   add 1 for integer division truncation; add 1 more for a minus sign.  */
#define INT_STRLEN_BOUND(t) ((sizeof (t) * CHAR_BIT - 1) * 302 / 1000 + 2)

#ifndef CHAR_MIN
# define CHAR_MIN TYPE_MINIMUM (char)
#endif

#ifndef CHAR_MAX
# define CHAR_MAX TYPE_MAXIMUM (char)
#endif

#ifndef SCHAR_MIN
# define SCHAR_MIN (-1 - SCHAR_MAX)
#endif

#ifndef SCHAR_MAX
# define SCHAR_MAX (CHAR_MAX == UCHAR_MAX ? CHAR_MAX / 2 : CHAR_MAX)
#endif

#ifndef UCHAR_MAX
# define UCHAR_MAX TYPE_MAXIMUM (unsigned char)
#endif

#ifndef SHRT_MIN
# define SHRT_MIN TYPE_MINIMUM (short int)
#endif

#ifndef SHRT_MAX
# define SHRT_MAX TYPE_MAXIMUM (short int)
#endif

#ifndef INT_MAX
# define INT_MAX TYPE_MAXIMUM (int)
#endif

#ifndef UINT_MAX
# define UINT_MAX TYPE_MAXIMUM (unsigned int)
#endif

#ifndef LONG_MAX
# define LONG_MAX TYPE_MAXIMUM (long)
#endif

#ifndef ULONG_MAX
# define ULONG_MAX TYPE_MAXIMUM (unsigned long)
#endif

#ifndef SIZE_MAX
# define SIZE_MAX TYPE_MAXIMUM (size_t)
#endif

#ifndef UINTMAX_MAX
# define UINTMAX_MAX TYPE_MAXIMUM (uintmax_t)
#endif

#ifndef OFF_T_MIN
# define OFF_T_MIN TYPE_MINIMUM (off_t)
#endif

#ifndef OFF_T_MAX
# define OFF_T_MAX TYPE_MAXIMUM (off_t)
#endif

#ifndef UID_T_MAX
# define UID_T_MAX TYPE_MAXIMUM (uid_t)
#endif

#ifndef GID_T_MAX
# define GID_T_MAX TYPE_MAXIMUM (gid_t)
#endif

#ifndef PID_T_MAX
# define PID_T_MAX TYPE_MAXIMUM (pid_t)
#endif

#ifndef CHAR_BIT
# define CHAR_BIT 8
#endif

/* Use this to suppress gcc's `...may be used before initialized' warnings. */
#ifdef lint
# define IF_LINT(Code) Code
#else
# define IF_LINT(Code) /* empty */
#endif

#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 8) || __STRICT_ANSI__
#  define __attribute__(x)
# endif
#endif

#ifndef ATTRIBUTE_NORETURN
# define ATTRIBUTE_NORETURN __attribute__ ((__noreturn__))
#endif

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif

#if defined strdupa
# define ASSIGN_STRDUPA(DEST, S)		\
  do { DEST = strdupa(S); } while (0)
#else
# define ASSIGN_STRDUPA(DEST, S)		\
  do						\
    {						\
      const char *s_ = (S);			\
      size_t len_ = strlen (s_) + 1;		\
      char *tmp_dest_ = (char *) alloca (len_);	\
      DEST = memcpy (tmp_dest_, (s_), len_);	\
    }						\
  while (0)
#endif

#endif /* SYS2_H */
