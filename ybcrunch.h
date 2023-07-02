/*Functions to crunch and uncrunch raw yb encoding
Raw encoding is expected to be aligned to 292 byte boundaries*/
#ifndef YBC
#define YBC
#include "yb.h"
#include <inttypes.h>
#include <stdio.h>

//condense raw (292 byte aligned) encoding, at worst inflates by 1 byte
uint8_t *yb_crunch(yb *g, uint8_t *enc, size_t cnt, size_t *ret_cnt);
//uncrunch back to raw (stride aligned) encoding
uint8_t *yb_uncrunch(FILE *fin, uint32_t sector_cnt, int *stride);
#endif
