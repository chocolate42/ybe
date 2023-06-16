#include "yb.h"
#include "ybe_common.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//vint: Standard vint with 7 bits per byte payload
static size_t bwrite_vint(uint32_t r, uint8_t *b){
	size_t i, ret=0, loc=0;
	for(i=28;i>=7;i-=7){
		if(r>=(1ull<<i))
			b[ret++]=((r>>i)&0x7F)|0x80;
	}
	b[ret++]=r&0x7F;
	return ret;
}

void stats_encode(yb *g){
	fprintf(stderr, "\nPrediction Stats:\n");
	if(g->cnt_conformant)fprintf(stderr, "Fully Predicted Sectors   : %6u / %6u\n", g->cnt_conformant, g->cnt_total);
	if(g->cnt_dadd)fprintf(stderr, "Unpredictable Address     : %6u / %6u\n", g->cnt_dadd, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_dint)fprintf(stderr, "Unpredictable Intermediate: %6u / %6u\n", g->cnt_dint, g->cnt_mode[YB_TYPE_M1]);
	if(g->cnt_dsub)fprintf(stderr, "Unpredictable Subheader   : %6u / %6u\n", g->cnt_dsub, (g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_dedc)fprintf(stderr, "Unpredictable EDC         : %6u / %6u\n", g->cnt_dedc, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_deccp)fprintf(stderr, "Unpredictable ECC P       : %6u / %6u\n", g->cnt_deccp, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]));
	if(g->cnt_deccq)fprintf(stderr, "Unpredictable ECC Q       : %6u / %6u\n", g->cnt_deccq, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]));
	if(g->cnt_zero_add||g->cnt_zero_sub||g->cnt_zero_edc||g->cnt_zero_eccp||g->cnt_zero_eccq)
		fprintf(stderr, "\nZeroed field stats:\n");
	if(g->cnt_zero_add)fprintf(stderr, "Zeroed Addresses: %6u / %6u\n", g->cnt_zero_add, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_zero_sub)fprintf(stderr, "Zeroed Subheaders: %6u / %6u\n", g->cnt_zero_sub, (g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_zero_edc)fprintf(stderr, "Zeroed EDC: %6u / %6u\n", g->cnt_zero_edc, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_zero_eccp)fprintf(stderr, "Zeroed ECC P: %6u / %6u\n", g->cnt_zero_eccp, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]));
	if(g->cnt_zero_eccq)fprintf(stderr, "Zeroed ECC Q: %6u / %6u\n", g->cnt_zero_eccq, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]));
	fprintf(stderr, "\nMode Stats:\n");
	if(g->cnt_mode[YB_TYPE_M1])fprintf(stderr, "Mode 1 Count        : %6u / %6u\n", g->cnt_mode[YB_TYPE_M1], g->cnt_total);
	if(g->cnt_mode[YB_TYPE_M2F1])fprintf(stderr, "Mode 2 Form 1 Count : %6u / %6u\n", g->cnt_mode[YB_TYPE_M2F1], g->cnt_total);
	if(g->cnt_mode[YB_TYPE_M2F2])fprintf(stderr, "Mode 2 Form 2 Count : %6u / %6u\n", g->cnt_mode[YB_TYPE_M2F2], g->cnt_total);
	if(g->cnt_mode[YB_TYPE_RAW])fprintf(stderr, "Raw Sector Count  : %6u / %6u\n", g->cnt_mode[YB_TYPE_RAW], g->cnt_total);
fprintf(stderr, "\n");
}

void ybe2bin(char *infile, char* outfile){
	FILE *fin=NULL, *fout=NULL;
	int stride;
	uint8_t crunch, data[2352], *enc=NULL, sector[2352];
	uint32_t i, sector_cnt;
	yb g={0};

	_if(!(fin=(strcmp(infile, "-")==0)?stdin:fopen(infile, "rb")), "Input stream cannot be NULL");
	ybe_read_header(fin, &sector_cnt, &crunch);
	enc=ybe_read_encoding(fin, sector_cnt, crunch, &stride);

	_if(!(fout=(strcmp(outfile, "-")==0)?stdout:fopen(outfile, "wb")), "Output stream cannot be NULL");
	g.sector_address=150;
	g.data=data;
	g.sector=sector;

	for(i=0;i<sector_cnt;++i){
		_if(yb_type_to_data_len(enc[i*stride])!=fread(data, 1, yb_type_to_data_len(enc[i*stride]), fin), "fread sector data failed");
		g.enc=enc+(i*stride);
		decode_sector(&g);
		_if(2352!=fwrite(sector, 1, 2352, fout), "fwrite sector failed");
	}

	_if((0!=strcmp(infile,"-"))&&(0!=fclose(fin)), "fclose input failed");
	_if((0!=strcmp(outfile,"-"))&&(0!=fclose(fout)), "fclose output failed");
	if(enc)
		free(enc);
}

void zeromodel_element(uint8_t type_byte, uint8_t *zero_byte, uint8_t mask, size_t len, uint8_t *enc, size_t *yb_loc){
	uint8_t zeroes[172]={0};
	if(type_byte&mask){
		if(0==memcmp(zeroes, enc+*yb_loc, len))
			(*zero_byte)|=mask;
		(*yb_loc)+=len;
	}
}

//figure out which unmodelled fields have zeroed data and return as "zero byte"
uint8_t zeromodel(uint8_t *enc){
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

void zerosuck_element(uint8_t type_byte, uint8_t zero_byte, uint8_t mask, size_t len, uint8_t *enc, size_t *yb_loc, uint8_t *out, size_t *out_loc){
	if(type_byte&mask){
		if(!(zero_byte&mask))
			*out_loc+=memcpy_cnt(out+*out_loc, enc+*yb_loc, len);
		*yb_loc+=len;
	}
}

//use "zero byte" to suck out zeroed fields from an encoding
size_t zerosuck(uint8_t *enc, uint8_t zero_byte, uint8_t *out){
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
void *realloc_managed(void *ptr, size_t *alloc, size_t loc){
	if(*alloc-loc<1024){
		_if(NULL==(ptr=realloc(ptr, *alloc+1024)), "realloc failed");
		*alloc=*alloc+1024;
	}
	return ptr;
}

/*
	RLE a set of bytes if possible in a few ways:
	* lenenc: There's up to two unique values, encoded as the values {u8:first u8:second[=0]} followed by a set of {vint:length}
	* pairenc: When there are many values, encode as a set of {u8:value, vint:length}
	Return the smallest valid representation prepended with a byte defining which is used

	Used to RLE type bytes and zero encoding
*/
uint8_t *rle_bytes(uint8_t *in, size_t in_cnt, size_t stride, size_t *out_cnt){
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
		free(best);
		best=NULL;
		*out_cnt=0;
	}
	return best;
}

void bin2ybe(char *infile, char* outfile){
	char *ybe="YBE";
	FILE *fin, *fout=NULL;
	size_t sector_alloc=0, sector_cnt=0, enc_size_tot=0, i, fread_res;
	uint8_t crunch=1, encoding_written=0, *enc=NULL, *sector=NULL, tmp[4];
	yb g={0};

	_if(!(fin=(strcmp(infile, "-")==0)?stdin:fopen(infile, "rb")), "Input stream cannot be NULL");
	g.sector_address=150;
	while(1){
		if(sector_alloc==sector_cnt){
			_if(!(enc=realloc(enc, (sector_cnt+1024)*292)), "realloc failed");
			_if(!(sector=realloc(sector, (sector_cnt+1024)*2352)), "realloc failed");
			sector_alloc+=1024;
		}
		if(!(fread_res=fread(sector+(sector_cnt*2352), 1, 2352, fin))){
			if(feof(fin))
				break;
			_("read nothing but not eof");
		}
		_if(2352!=fread_res, "input size not a multiple of 2352");

		g.enc=enc+(sector_cnt*292);
		g.sector=sector+(sector_cnt*2352);
		enc_size_tot+=encode_sector(&g);

		++sector_cnt;
	}
	_if((0!=strcmp(infile,"-"))&&(0!=fclose(fin)), "fclose input failed");

	if(outfile)
		_if(!(fout=(strcmp(outfile, "-")==0)?stdout:fopen(outfile, "wb")), "Output stream cannot be NULL");
	_if(fout&&(4!=fwrite(ybe, 1, 4, fout)), "fwrite magic failed");
	put32lsb(tmp, sector_cnt);
	_if(fout&&(4!=fwrite(tmp, 1, 4, fout)), "fwrite sector count failed");

	if(crunch && !encoding_written && (g.cnt_conformant==g.cnt_total)){//"perfect" encode method
		for(i=0;i<4;++i){
			if(g.cnt_mode[i])
				break;
		}
		if(g.cnt_mode[i]==g.cnt_total){//input is perfect
			crunch=i+1;
			_if(fout&&(1!=fwrite(&crunch, 1, 1, fout)), "fwrite encoding failed");
			encoding_written=1;
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
	if(crunch && !encoding_written){
		uint8_t *zero_encoding, *type_rle, *zero_rle, largest=0, sucker[292];
		size_t sucker_cnt, type_rle_cnt, zero_rle_cnt, zero_saving=0, zero_done=0;
		size_t mode5_size=1, raw_size=0;
		//work out if mode5 encoding would be smaller than raw
		for(i=0;i<sector_cnt;++i)
			raw_size+=yb_type_to_enc_len(enc[i*292]);

		//type encoding
		type_rle=rle_bytes(enc, sector_cnt, 292, &type_rle_cnt);
		if(type_rle)
			mode5_size+=type_rle_cnt;
		else
			mode5_size+=(1+sector_cnt);

		//zero encoding
		zero_saving=(g.cnt_zero_add*3)+(g.cnt_zero_sub*4)+(g.cnt_zero_edc*4)+(g.cnt_zero_eccp*172)+(g.cnt_zero_eccq*104);
		if(zero_saving){
			zero_encoding=calloc(sector_cnt, 1);
			for(i=0;i<sector_cnt;++i)
				zero_encoding[i]=zeromodel(enc+(i*292));
			zero_rle=rle_bytes(zero_encoding, sector_cnt, 1, &zero_rle_cnt);
			if(zero_rle){//rle worked
				if(zero_rle_cnt<zero_saving){//zero encoding is worth it
					zero_done=1;
					mode5_size+=zero_rle_cnt;
				}
				else
					++mode5_size;
			}
			else{//rle failed
				if(sector_cnt<zero_saving){//zero encoding is worth it
					zero_done=1;
					mode5_size+=(1+sector_cnt);
				}
				else
					++mode5_size;
			}
		}
		else
			++mode5_size;

		if(zero_done)
			mode5_size+=(raw_size-(sector_cnt+zero_saving));
		else
			mode5_size+=(raw_size-sector_cnt);

		if(mode5_size<raw_size){//mode5 is beneficial
			crunch=5;
			_if(fout&&(1!=fwrite(&crunch, 1, 1, fout)), "fwrite crunch byte failed");
			//compute largest type byte
			largest=*enc;
			for(i=1;i<sector_cnt;++i){
				if(yb_type_to_enc_len(largest)<yb_type_to_enc_len(enc[i*292]))
					largest=enc[i*292];
			}
			_if(fout&&(1!=fwrite(&largest, 1, 1, fout)), "fwrite largest type byte failed");

			//type encoding
			if(type_rle)
				_if(fout&&(type_rle_cnt!=fwrite(type_rle, 1, type_rle_cnt, fout)), "fwrite type rle failed");
			else{
				*tmp=0;
				_if(fout&&(1!=fwrite(tmp, 1, 1, fout)), "fwrite raw type header failed");
				for(i=0;i<sector_cnt;++i)
					_if(fout&&(1!=fwrite(enc+(i*292), 1, 1, fout)), "fwrite raw type failed");
			}

			//zero encoding
			*tmp=3;
			if(zero_done){
				if(zero_rle)
					_if(fout&&(zero_rle_cnt!=fwrite(zero_rle, 1, zero_rle_cnt, fout)), "fwrite zero rle failed");
				else{
					*tmp=0;
					_if(fout&&(1!=fwrite(tmp, 1, 1, fout)), "fwrite zero raw header failed");
					_if(fout&&(1!=fwrite(zero_encoding, 1, sector_cnt, fout)), "fwrite zero raw failed");
				}
			}
			else
				_if(fout&&(1!=fwrite(tmp, 1, 1, fout)), "fwrite no zero header failed");

			//dump remaining unmodelled data
			if(zero_done){
				for(i=0;i<sector_cnt;++i){
					if(zero_encoding[i]){
						sucker_cnt=zerosuck(enc+(i*292), zero_encoding[i], sucker);
						_if(fout&&(sucker_cnt!=fwrite(sucker, 1, sucker_cnt, fout)), "fwrite zerosuck encoding failed");
					}
					else
						_if(fout&&((yb_type_to_enc_len(enc[i*292])-1)!=fwrite(enc+(i*292)+1, 1, yb_type_to_enc_len(enc[i*292])-1, fout)), "fwrite raw encoding failed");
				}
			}
			else{//quicker path
				for(i=0;i<sector_cnt;++i)
					_if(fout&&((yb_type_to_enc_len(enc[i*292])-1)!=fwrite(enc+(i*292)+1, 1, yb_type_to_enc_len(enc[i*292])-1, fout)), "fwrite raw encoding failed");
			}
			fprintf(stderr, "Raw encoding reduced by %zu bytes with mode5 (%f%%)\n", raw_size-mode5_size, (100.0*mode5_size)/raw_size);
			encoding_written=1;
		}
	}
	if(!encoding_written){//"raw" encode method
		crunch=0;
		_if(fout&&(1!=fwrite(&crunch, 1, 1, fout)), "fwrite encoding type failed");
		for(i=0;i<sector_cnt;++i)
			_if(fout&&(yb_type_to_enc_len(enc[i*292])!=fwrite(enc+(i*292), 1, yb_type_to_enc_len(enc[i*292]), fout)), "fwrite encoding failed");
	}

	for(i=0;i<sector_cnt;++i)
		_if(fout&&(yb_type_to_data_len(enc[i*292])!=fwrite(sector+(i*2352)+yb_type_to_data_loc(enc[i*292]), 1, yb_type_to_data_len(enc[i*292]), fout)), "fwrite data failed");

	stats_encode(&g);
	_if(fout&&(0!=strcmp(outfile,"-"))&&(0!=fclose(fout)), "fclose output failed");
	if(enc)
		free(enc);
	if(sector)
		free(sector);
}

char *gen_outpath(char *inpath, int trunc){
	char *outpath;
	_if(!(outpath=malloc(strlen(inpath)+5)), "malloc failed");
	sprintf(outpath, "%s.ybe", inpath);
	outpath[strlen(inpath)+trunc]=0;
	return outpath;
}

void help(){
	fprintf(stderr,  "ybe v0.2\n\nEncode:\n ybe src.bin\n ybe src.bin dest.ybe\n ybe e src.bin dest.ybe\n\n"
		"Decode:\n unybe src.ybe\n unybe src.ybe dest.bin\n ybe d src.ybe dest.bin\n\n"
		"Test:\n ybe t src.bin\n\n"
		"- can take the place of src/dest to pipe with stdin/stdout\n\n");
}

int main(int argc, char *argv[]){
	char *in=NULL, *out=NULL;
	int enc=1;
	void (*func[])(char*, char*)={ybe2bin, bin2ybe};

	if(argc==1 || (argc>=2 && ((strcmp(argv[1], "-h")==0)||(strcmp(argv[1], "--help")==0)))){
		help();
		return 0;
	}

	if(argc<4){
		in=argv[1];
		enc=str_ends_with(argv[0], "unybe")?0:enc;
	}
	if(argc==2)//ybe src || unybe src
		out=gen_outpath(argv[(argc==4)?2:1], (enc*8)-4);
	else if((argc==3)&&(strcmp(argv[1], "t")==0))//[un]ybe t src
		in=argv[2];
	else if(argc==3)//ybe src dest || unybe src dest
		out=argv[2];
	else if(argc==4){//[un]ybe e src dest || [un]ybe d src dest
		in=argv[2];
		out=argv[3];
		if(strcmp(argv[1], "d")==0)
			enc=0;
		else if(strcmp(argv[1], "e")!=0){
			help();
			_("Unknown mode");
		}
	}
	else{
		help();
		_("Too many args");
	}

	eccedc_init();
	fprintf(stderr, "%scode '%s' to '%s'\n", enc?"En":"De", in, out);
	func[enc](in, out);
	if(argc==2)
		free(out);

	return 0;
}
