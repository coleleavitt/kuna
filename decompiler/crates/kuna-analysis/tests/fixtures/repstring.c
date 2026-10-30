/* Fixture for `repstring`: copies and fills gcc -Os inlines as rep movs/stos.
   gcc -Os -fno-pic -nostdlib -static -Wl,-e,copy_n repstring.c -o repstring_x86_64
   gcc -m32 -Os -fno-pic -nostdlib -static -Wl,-e,copy_n repstring.c -o repstring_i386 */
#include <string.h>
struct big { long a[8]; };
struct rec { char name[40]; int id; };
void copy_struct(struct big *d, const struct big *s) { *d = *s; }
void copy_n(char *d, const char *s, unsigned long n) { memcpy(d, s, n); }
void fill_n(char *d, int c, unsigned long n) { memset(d, c, n); }
void zero_rec(struct rec *r) { memset(r, 0, sizeof *r); }
char *copy_end(char *d, const char *s, unsigned long n) { return (char *)memcpy(d, s, n) + n; }
