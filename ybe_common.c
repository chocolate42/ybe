#include "yb.h"
#include "ybe_common.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

void _(char *s){
	fprintf(stderr, "Error: %s\n", s);
	exit(1);
}

void _if(_Bool goodbye, char *s){
	if(goodbye)
		_(s);
}

_Bool str_ends_with(const char *str, const char *end){
	return (strlen(str)>=strlen(end)) && (strcmp(str+strlen(str)-strlen(end), end)==0);
}

void ybe_read_header(FILE *fin, uint32_t *sector_cnt){
	uint8_t tmp[4];
	_if(4!=fread(tmp, 1, 4, fin), "fread magic failed");
	_if((tmp[0]!='Y')||(tmp[1]!='B')||(tmp[2]!='E')||(tmp[3]!=0), "magic mismatch");
	_if(4!=fread(tmp, 1, 4, fin), "fread sector count failed");
	*sector_cnt=get32lsb(tmp);
	_if(!sector_cnt, "sector count cannot be zero");
}
