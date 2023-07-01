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

//vint: Standard vint with 7 bits per byte payload
static size_t fread_vint(uint32_t *n, FILE *fin){
	size_t c=0;
	uint8_t t;
	uint32_t r=0;
	_if(1!=fread(&t, 1, 1, fin), "fread vint failed");
	for(c=0;t&0x80;++c){
		r=(r<<7)|(t&0x7F);
		_if(1!=fread(&t, 1, 1, fin), "fread vint failed");
	}
	*n=((r<<7)|t);
	return c+1;
}

static uint8_t *unrle_bytes(FILE *fin, int stride, uint32_t sector_cnt){
	uint8_t *out=NULL, head, curr_val=0, val[2];
	uint32_t curr_run;
	size_t i, j;
	_if(1!=fread(&head, 1, 1, fin), "fread rle header failed");
	switch(head){
		case 0://raw
			out=calloc(sector_cnt, stride);
			for(i=0;i<sector_cnt;++i)
				_if(1!=fread(out+(i*stride), 1, 1, fin), "fread rle val failed");
			return out;

		case 1://pairenc
			out=calloc(sector_cnt, stride);
			for(i=0;i<sector_cnt;i+=j){
				_if(1!=fread(&curr_val, 1, 1, fin), "fread rle val failed");
				fread_vint(&curr_run, fin);
				for(j=0;j<=curr_run;++j)
					out[(i+j)*stride]=curr_val;
			}
			assert(i==sector_cnt);
			return out;

		case 2://lenenc
			out=calloc(sector_cnt, stride);
			_if(2!=fread(val, 1, 2, fin), "fread rle pair failed");
			for(i=0;i<sector_cnt;i+=j){
				fread_vint(&curr_run, fin);
				for(j=0;j<=curr_run;++j)
					out[(i+j)*stride]=val[curr_val&1];
				++curr_val;
			}
			assert(i==sector_cnt);
			return out;

		case 3://not present
			return out;

		default:
			_("Unknown rle header, invalid input or outdated program");
	}
	return NULL;
}

size_t unsuck_element(uint8_t type_byte, uint8_t zero_byte, uint8_t mask, size_t len, FILE *fin, uint8_t *out){
	if(type_byte&mask){
		if(zero_byte&mask)
			memset(out, 0, len);
		else
			_if(len!=fread(out, 1, len, fin), "fread field failed");
		return len;
	}
	return 0;
}

//reverse zerosuck
static void unzerosuck(uint8_t *enc, uint8_t zero_byte, FILE *fin){
	size_t yb_loc=1;
	if(((*enc)&3)==YB_TYPE_RAW)
		return;

	yb_loc+=unsuck_element(*enc, zero_byte, YB_ADD, 3, fin, enc+yb_loc);
	if(((*enc)&3)==YB_TYPE_M1){
		yb_loc+=unsuck_element(*enc, zero_byte, YB_EDC, 4, fin, enc+yb_loc);
		yb_loc+=unsuck_element(*enc, zero_byte, YB_SUB, 8, fin, enc+yb_loc);
		yb_loc+=unsuck_element(*enc, zero_byte, YB_ECCP, 172, fin, enc+yb_loc);
		yb_loc+=unsuck_element(*enc, zero_byte, YB_ECCQ, 104, fin, enc+yb_loc);
		return;
	}

	yb_loc+=unsuck_element(*enc, zero_byte, YB_SUB, 4, fin, enc+yb_loc);
	if(((*enc)&3)==YB_TYPE_M2F1){
		yb_loc+=unsuck_element(*enc, zero_byte, YB_EDC, 4, fin, enc+yb_loc);
		yb_loc+=unsuck_element(*enc, zero_byte, YB_ECCP, 172, fin, enc+yb_loc);
		yb_loc+=unsuck_element(*enc, zero_byte, YB_ECCQ, 104, fin, enc+yb_loc);
	}
	else//YB_TYPE_M2F2
		yb_loc+=unsuck_element(*enc, zero_byte, YB_EDC, 4, fin, enc+yb_loc);
	return;
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

void *ybe_read_encoding(FILE *fin, uint32_t sector_cnt, uint8_t crunch, int *stride){
	uint8_t *enc, *zeromap, largest;
	uint32_t i;
	switch(crunch){//read encoding
		case 0://raw
			*stride=292;
			_if(!(enc=malloc(sector_cnt*292)), "malloc failed");
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
			*stride=0;
			_if(!(enc=malloc(1)), "malloc failed");
			*enc=crunch-1;
			break;

		case 5:
			//largest
			_if(1!=fread(&largest, 1, 1, fin), "fread largest type byte failed");
			*stride=yb_type_to_enc_len(largest);
			_if(!(enc=malloc(sector_cnt**stride)), "malloc failed");

			//decode type bytes to where they should be in enc
			enc=unrle_bytes(fin, *stride, sector_cnt);

			//decode zero bytes
			zeromap=unrle_bytes(fin, 1, sector_cnt);

			//unsuck zerosuck encoding
			for(i=0;i<sector_cnt;++i)
				unzerosuck(enc+(i**stride), zeromap?zeromap[i]:0, fin);
			break;

		default:
			_("Unknown encode type, invalid input or program outdated");
	}
	fprintf(stderr, "encoding read\n");
	return enc;
}
