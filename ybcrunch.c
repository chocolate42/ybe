#include "ybcrunch.h"
#include "ybe_common.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* 
	zeromodel() generates a bitfield of zeroed unmodelled elements
	zerosuck() sucks zeroed unmodelled elements from a raw encoding
	rle_bytes() does basic rle on a set of bytes

	yb_crunch() may use the above to reduce the footprint of the encoding
*/

static void zeromodel_element(uint8_t type_byte, uint8_t *zero_byte, uint8_t mask, size_t len, uint8_t *enc, size_t *yb_loc){
	uint8_t zeroes[172]={0};
	if(type_byte&mask){
		if(0==memcmp(zeroes, enc+*yb_loc, len))
			(*zero_byte)|=mask;
		(*yb_loc)+=len;
	}
}

//figure out which unmodelled fields have zeroed data and return as "zero byte"
static uint8_t zeromodel(uint8_t *enc){
	uint8_t ret=0;
	size_t yb_loc=1;
	if(((*enc)&3)==YB_TYPE_RAW)
		return ret;

	zeromodel_element(*enc, &ret, YB_ADD, 3, enc, &yb_loc);
	if(((*enc)&3)==YB_TYPE_M1){
		zeromodel_element(*enc, &ret, YB_EDC, 4, enc, &yb_loc);
		zeromodel_element(*enc, &ret, YB_SUB, 8, enc, &yb_loc);
		zeromodel_element(*enc, &ret, YB_ECCP, 172, enc, &yb_loc);
		zeromodel_element(*enc, &ret, YB_ECCQ, 104, enc, &yb_loc);
		return ret;
	}

	zeromodel_element(*enc, &ret, YB_SUB, 4, enc, &yb_loc);
	if(((*enc)&3)==YB_TYPE_M2F1){
		zeromodel_element(*enc, &ret, YB_EDC, 4, enc, &yb_loc);
		zeromodel_element(*enc, &ret, YB_ECCP, 172, enc, &yb_loc);
		zeromodel_element(*enc, &ret, YB_ECCQ, 104, enc, &yb_loc);
	}
	else//YB_TYPE_M2F2
		zeromodel_element(*enc, &ret, YB_EDC, 4, enc, &yb_loc);
	return ret;
}

static void zerosuck_element(uint8_t type_byte, uint8_t zero_byte, uint8_t mask, size_t len, uint8_t *enc, size_t *yb_loc, uint8_t *out, size_t *out_loc){
	if(type_byte&mask){
		if(!(zero_byte&mask))
			*out_loc+=memcpy_cnt(out+*out_loc, enc+*yb_loc, len);
		*yb_loc+=len;
	}
}

//use "zero byte" to suck out zeroed fields from an encoding
static size_t zerosuck(uint8_t *enc, uint8_t zero_byte, uint8_t *out){
	size_t yb_loc=1, out_loc=0;
	if(((*enc)&3)==YB_TYPE_RAW)
		return out_loc;

	zerosuck_element(*enc, zero_byte, YB_ADD, 3, enc, &yb_loc, out, &out_loc);
	if(((*enc)&3)==YB_TYPE_M1){
		zerosuck_element(*enc, zero_byte, YB_EDC, 4, enc, &yb_loc, out, &out_loc);
		zerosuck_element(*enc, zero_byte, YB_SUB, 8, enc, &yb_loc, out, &out_loc);
		zerosuck_element(*enc, zero_byte, YB_ECCP, 172, enc, &yb_loc, out, &out_loc);
		zerosuck_element(*enc, zero_byte, YB_ECCQ, 104, enc, &yb_loc, out, &out_loc);
		return out_loc;
	}

	zerosuck_element(*enc, zero_byte, YB_SUB, 4, enc, &yb_loc, out, &out_loc);
	if(((*enc)&3)==YB_TYPE_M2F1){
		zerosuck_element(*enc, zero_byte, YB_EDC, 4, enc, &yb_loc, out, &out_loc);
		zerosuck_element(*enc, zero_byte, YB_ECCP, 172, enc, &yb_loc, out, &out_loc);
		zerosuck_element(*enc, zero_byte, YB_ECCQ, 104, enc, &yb_loc, out, &out_loc);
	}
	else//YB_TYPE_M2F2
		zerosuck_element(*enc, zero_byte, YB_EDC, 4, enc, &yb_loc, out, &out_loc);
	return out_loc;
}

//increase buffer if necessary
static void *realloc_managed(void *ptr, size_t *alloc, size_t loc){
	if(*alloc-loc<1024){
		_if(NULL==(ptr=realloc(ptr, *alloc+1024)), "realloc failed");
		*alloc=*alloc+1024;
	}
	return ptr;
}

//vint: Standard vint with 7 bits per byte payload
static size_t bwrite_vint(uint32_t r, uint8_t *b){
	size_t i, ret=0;
	for(i=28;i>=7;i-=7){
		if(r>=(1ull<<i))
			b[ret++]=((r>>i)&0x7F)|0x80;
	}
	b[ret++]=r&0x7F;
	return ret;
}

/*
	RLE a set of bytes if possible in a few ways:
	* lenenc: There's up to two unique values, encoded as the values {u8:first u8:second[=0]} followed by a set of {vint:length}
	* pairenc: When there are many values, encode as a set of {u8:value, vint:length}
	* raw: If lenenc and pairenc are both larger than the input, just output raw
	Return the smallest valid representation prepended with a byte defining which is used

	Used to RLE type bytes and zero encoding
*/
static uint8_t *rle_bytes(uint8_t *in, size_t in_cnt, size_t stride, size_t *out_cnt){
	uint8_t *best, *pairenc=NULL, *lenenc=NULL, len[2]={0};
	size_t curr_run=0, pairenc_cnt=0, lenenc_cnt=0, pairenc_alloc=2048, lenenc_alloc=2048, i;
	int lenenc_possible=1, first=1;
	pairenc=realloc(pairenc, 2048);
	lenenc=realloc(lenenc, 2048);
	len[0]=*in;//the first of a pair
	pairenc[pairenc_cnt++]=1;
	lenenc[lenenc_cnt++]=2;
	for(i=1;i<in_cnt;++i){
		if(in[(i-1)*stride]==in[i*stride])
			++curr_run;
		else{
			if(first){//first time encountering second value
				len[1]=in[i*stride];
				lenenc[lenenc_cnt++]=len[0];//write pair
				lenenc[lenenc_cnt++]=len[1];
				first=0;
			}
			if(lenenc_possible && len[0]!=in[i*stride] && len[1]!=in[i*stride]){
				free(lenenc);
				lenenc_possible=0;//more than 2 type bytes, lenenc not possible
			}
			if(lenenc_possible){
				lenenc=realloc_managed(lenenc, &lenenc_alloc, lenenc_cnt);
				lenenc_cnt+=bwrite_vint(curr_run, lenenc+lenenc_cnt);
			}
			{//pairenc
				pairenc=realloc_managed(pairenc, &pairenc_alloc, pairenc_cnt);
				pairenc[pairenc_cnt++]=in[(i-1)*stride];
				pairenc_cnt+=bwrite_vint(curr_run, pairenc+pairenc_cnt);
			}
			curr_run=0;
		}
	}
	if(first){//write "pair" (second value unused 0)
		lenenc[lenenc_cnt++]=len[0];
		lenenc[lenenc_cnt++]=len[1];
		lenenc_cnt+=bwrite_vint(curr_run, lenenc+lenenc_cnt);
	}
	else if(lenenc_possible){
		lenenc=realloc_managed(lenenc, &lenenc_alloc, lenenc_cnt);
		lenenc_cnt+=bwrite_vint(curr_run, lenenc+lenenc_cnt);
	}
	{//pairenc
		pairenc=realloc_managed(pairenc, &pairenc_alloc, pairenc_cnt);
		pairenc[pairenc_cnt++]=in[(i-1)*stride];
		pairenc_cnt+=bwrite_vint(curr_run, pairenc+pairenc_cnt);
	}

	//return best representation if any
	best=pairenc;//set pairenc as initial best
	*out_cnt=pairenc_cnt;
	if(lenenc_possible){
		if(lenenc_cnt<*out_cnt){//lenenc better than pairenc
			best=lenenc;
			*out_cnt=lenenc_cnt;
			free(pairenc);
		}
		else
			free(lenenc);
	}
	if(in_cnt+1<=*out_cnt){//better not to RLE
		best=realloc(best, 1+in_cnt);
		best[0]=0;
		for(i=0;i<in_cnt;++i)
			best[i+1]=in[i*stride];
		*out_cnt=1+in_cnt;
	}
	return best;
}

//condense raw encoding, at worst inflates by 1 byte
uint8_t *yb_crunch(yb *g, uint8_t *enc, size_t cnt, size_t *ret_cnt){
	size_t i, j=1, raw_size=0;
	uint8_t *ret=NULL;

	if(g->cnt_conformant==g->cnt_total){//"perfect" encode method
		for(i=0;i<4;++i){
			if(g->cnt_mode[i])
				break;
		}
		if(g->cnt_mode[i]==g->cnt_total){//input is perfect
			ret=malloc(1);
			ret[0]=i+1;
			*ret_cnt=1;
			return ret;
		}
	}

	/* mode5: RLE + zerosuck
		* RLE type bytes if beneficial
		* encode fields filled with zeroes if beneficial
		mode5_encoding{
			uint8_t largest; //type byte of the largest encoding, decode memory optimisation
			uint8_t type_encoding_type;//0=raw, 1=pairenc, 2=lenenc
			void *type_byte_encoding;
			uint8_t zero_encoding_type;//0=raw, 1=pairenc, 2=lenenc, 3=not present
			void *zero_encoding;
			void *unmodelled;//all remaining unmodelled fields
		}
	*/
	{
		uint8_t *zero_encoding=NULL, *type_rle, *zero_rle=NULL, sucker[292];
		size_t sucker_cnt, type_rle_cnt, zero_rle_cnt, zero_saving=0, zero_done=0;
		size_t mode5_size=2;//crunch byte and largest byte
		//work out if mode5 encoding would be smaller than raw
		for(i=0;i<cnt;++i)
			raw_size+=yb_type_to_enc_len(enc[i*292]);
		mode5_size+=(raw_size-cnt);//raw encoding minus type bytes

		//type encoding
		type_rle=rle_bytes(enc, cnt, 292, &type_rle_cnt);
		mode5_size+=type_rle_cnt;

		//zero encoding
		zero_saving=(g->cnt_zero_add*3)+(g->cnt_zero_sub*4)+(g->cnt_zero_edc*4)+(g->cnt_zero_eccp*172)+(g->cnt_zero_eccq*104);
		if(zero_saving){
			zero_encoding=calloc(cnt, 1);
			for(i=0;i<cnt;++i)
				zero_encoding[i]=zeromodel(enc+(i*292));
			zero_rle=rle_bytes(zero_encoding, cnt, 1, &zero_rle_cnt);
			if(zero_rle_cnt<zero_saving){//zero encoding is worth it
				zero_done=1;
				mode5_size-=(zero_saving-zero_rle_cnt);//add rle encoding, minus zero bytes sucked out
			}
			else{//zero encoding not worth it
				free(zero_encoding);
				free(zero_rle);
				++mode5_size;
			}
		}
		else//no zeroed fields to suck
			++mode5_size;

		if(mode5_size<raw_size){//mode5 is beneficial
			ret=malloc(mode5_size);
			*ret_cnt=mode5_size;
			ret[0]=5;
			//compute largest type byte
			ret[j]=*enc;
			for(i=1;i<cnt;++i){
				if(yb_type_to_enc_len(ret[j])<yb_type_to_enc_len(enc[i*292]))
					ret[j]=enc[i*292];
			}
			++j;

			//type encoding
			j+=memcpy_cnt(ret+j, type_rle, type_rle_cnt);
			free(type_rle);

			if(zero_done){//zero_rle + zerosucked data
				j+=memcpy_cnt(ret+j, zero_rle, zero_rle_cnt);
				free(zero_rle);
				for(i=0;i<cnt;++i){
					sucker_cnt=zerosuck(enc+(i*292), zero_encoding[i], sucker);
					j+=memcpy_cnt(ret+j, sucker, sucker_cnt);
				}
				free(zero_encoding);
			}
			else{//raw data
				ret[j++]=3;//zero_rle not present
				for(i=0;i<cnt;++i)
					j+=memcpy_cnt(ret+j, enc+(i*292)+1, yb_type_to_enc_len(enc[i*292])-1);
			}
			assert(j==*ret_cnt);
			return ret;
		}
	}

	//"raw" encode method
	ret=malloc(raw_size+1);
	*ret_cnt=raw_size+1;
	ret[0]=0;
	for(i=0;i<cnt;++i)
		j+=memcpy_cnt(ret+j, enc+(i*292), yb_type_to_enc_len(enc[i*292]));
	return ret;
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

uint8_t *yb_uncrunch(FILE *fin, uint32_t sector_cnt, int *stride){
	uint8_t crunch, *enc=NULL, *zeromap, largest;
	uint32_t i;
	_if(1!=fread(&crunch, 1, 1, fin), "fread encode type failed");
	switch(crunch){//read encoding
		case 0://raw
			*stride=292;
			_if(!(enc=malloc(sector_cnt*292)), "malloc failed");
			for(i=0;i<sector_cnt;++i){
				_if(1!=fread(enc+(i*292), 1, 1, fin), "fread sector type byte failed");
				if(1!=yb_type_to_enc_len(enc[i*292]))
					_if((yb_type_to_enc_len(enc[i*292])-1)!=fread(enc+(i*292)+1, 1, yb_type_to_enc_len(enc[i*292])-1, fin), "fread sector encoding failed");
			}
			//optional post-read stride shrink TODO
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

		case 5://mode 5, (type rle, zero rle, zerosuck, stride optimisation)
			//largest
			_if(1!=fread(&largest, 1, 1, fin), "fread largest type byte failed");
			*stride=yb_type_to_enc_len(largest);

			//decode type bytes to where they should be in enc
			enc=unrle_bytes(fin, *stride, sector_cnt);

			//decode zero bytes
			zeromap=unrle_bytes(fin, 1, sector_cnt);

			//unsuck zerosuck encoding
			for(i=0;i<sector_cnt;++i)
				unzerosuck(enc+(i**stride), zeromap?zeromap[i]:0, fin);
			if(zeromap)
				free(zeromap);
			break;

		default:
			_("Unknown encode type, invalid input or program outdated");
	}
	fprintf(stderr, "encoding read\n");
	return enc;
}
