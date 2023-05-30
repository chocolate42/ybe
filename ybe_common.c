#include "yb.h"
#include "ybe_common.h"
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

void ybe_read_header(FILE *fin, uint32_t *sector_cnt, uint8_t *crunch){
	uint8_t tmp[4];
	_if(4!=fread(tmp, 1, 4, fin), "fread magic failed");
	_if((tmp[0]!='Y')||(tmp[1]!='B')||(tmp[2]!='E')||(tmp[3]!=0), "magic mismatch");
	_if(4!=fread(tmp, 1, 4, fin), "fread sector count failed");
	*sector_cnt=get32lsb(tmp);
	_if(!sector_cnt, "sector count cannot be zero");
	_if(1!=fread(crunch, 1, 1, fin), "fread encode type failed");
}

void *ybe_read_encoding(FILE *fin, uint32_t sector_cnt, uint8_t crunch){
	uint8_t *enc;
	uint32_t i;
	_if(!(enc=malloc(sector_cnt*292)), "malloc failed");
	switch(crunch){//read encoding
		case 0://raw
			for(i=0;i<sector_cnt;++i){
				_if(1!=fread(enc+(i*292), 1, 1, fin), "fread sector type byte failed");
				if(1!=yb_type_to_enc_len(enc[i*292]))
					_if((yb_type_to_enc_len(enc[i*292])-1)!=fread(enc+(i*292)+1, 1, yb_type_to_enc_len(enc[i*292])-1, fin), "fread sector encoding failed");
			}
			break;

		//perfectly modelled with a single sector type
		case 1:
		case 2:
		case 3:
		case 4:
			for(i=0;i<sector_cnt;++i)
				enc[i*292]=crunch-1;
			break;

		default:
			_("Unknown encode type, invalid input or program outdated");
	}
	return enc;
}
