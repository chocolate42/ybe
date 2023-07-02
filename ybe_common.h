#ifndef YBE_COMMON
#define YBE_COMMON

#include <inttypes.h>
#include <stdio.h>

void _(char *s);
void _if(_Bool goodbye, char *s);
_Bool str_ends_with(const char *str, const char *end);
void ybe_read_header(FILE *fin, uint32_t *sector_cnt);

#endif
