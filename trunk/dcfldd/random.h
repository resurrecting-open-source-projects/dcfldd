#ifndef RANDOM_H
#define RANDOM_H 1

#include <string.h>

extern void init_genrand(unsigned long);
extern void init_by_array(unsigned long [], int);
extern unsigned long genrand_int32(void);
extern long genrand_int31(void);
extern double genrand_real1(void);
extern double genrand_real2(void);
extern double genrand_real3(void);
extern double genrand_res53(void);

extern void genrand_buf(char *, size_t);

#endif /* RANDOM_H */
