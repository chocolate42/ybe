#include "yb.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef YB_MIN
int strcmp(const char *s1, const char *s2){
	size_t n;
	for(n=0;;++n){
		if(s1[n]!=s2[n])
			return 1;
		if(!s1[n])
			return 0;
	}
}
size_t strlen(const char *s){
	size_t n;
	for(n=0;s[n];++n);
	return n;
}
#else
#include <string.h>
#endif

static inline void _(char *s){
	fprintf(stderr, "Error: %s\n", s);
	exit(1);
}

static inline void _if(_Bool goodbye, char *s){
	if(goodbye)
		_(s);
}

void stats_encode(yb *g){
	fprintf(stderr, "\nPrediction Stats:\n");
	if(g->cnt_conformant)fprintf(stderr, "Fully Predicted Sectors    : %u / %u\n", g->cnt_conformant, g->cnt_total);
	if(g->cnt_dadd)fprintf(stderr, "Unpredictable Addresses    : %u / %u\n", g->cnt_dadd, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_dint)fprintf(stderr, "Unpredictable Intermediates: %u / %u\n", g->cnt_dint, g->cnt_mode[YB_TYPE_M1]);
	if(g->cnt_dsub)fprintf(stderr, "Unpredictable Subheaders   : %u / %u\n", g->cnt_dsub, (g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_dedc)fprintf(stderr, "Unpredictable EDC Count    : %u / %u\n", g->cnt_dedc, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]+g->cnt_mode[YB_TYPE_M2F2]));
	if(g->cnt_deccp)fprintf(stderr, "Unpredictable ECC P Fields : %u / %u\n", g->cnt_deccp, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]));
	if(g->cnt_deccq)fprintf(stderr, "Unpredictable ECC Q Fields : %u / %u\n", g->cnt_deccq, (g->cnt_mode[YB_TYPE_M1]+g->cnt_mode[YB_TYPE_M2F1]));
	fprintf(stderr, "\nMode Stats:\n");
	if(g->cnt_mode[YB_TYPE_M1])fprintf(stderr, "Mode 1 Count        : %u / %u\n", g->cnt_mode[YB_TYPE_M1], g->cnt_total);
	if(g->cnt_mode[YB_TYPE_M2F1])fprintf(stderr, "Mode 2 Form 1 Count : %u / %u\n", g->cnt_mode[YB_TYPE_M2F1], g->cnt_total);
	if(g->cnt_mode[YB_TYPE_M2F2])fprintf(stderr, "Mode 2 Form 2 Count : %u / %u\n", g->cnt_mode[YB_TYPE_M2F2], g->cnt_total);
	if(g->cnt_mode[YB_TYPE_RAW])fprintf(stderr, "Raw Sector Count  : %u / %u\n", g->cnt_mode[YB_TYPE_RAW], g->cnt_total);
	fprintf(stderr, "\n");
}

void ybe2bin(char *infile, char* outfile){
	FILE *fin=NULL, *fout=NULL;
	uint8_t crunch, data[2352], *enc=NULL, sector[2352], tmp[4];
	uint32_t i, sector_cnt;
	yb g={0};

	_if(!(fin=(strcmp(infile, "-")==0)?stdin:fopen(infile, "rb")), "Input stream cannot be NULL");
	_if(4!=fread(tmp, 1, 4, fin), "fread magic failed");
	_if((tmp[0]!='Y')||(tmp[1]!='B')||(tmp[2]!='E')||(tmp[3]!=0), "magic mismatch");
	_if(4!=fread(tmp, 1, 4, fin), "fread sector count failed");
	sector_cnt=get32lsb(tmp);
	_if(!sector_cnt, "sector count cannot be zero");
	_if(1!=fread(&crunch, 1, 1, fin), "fread encode type failed");

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
	_if(!(fout=(strcmp(outfile, "-")==0)?stdout:fopen(outfile, "wb")), "Output stream cannot be NULL");
	g.sector_address=150;
	g.data=data;
	g.sector=sector;

	for(i=0;i<sector_cnt;++i){
		_if(yb_type_to_data_len(enc[i*292])!=fread(data, 1, yb_type_to_data_len(enc[i*292]), fin), "fread sector data failed");
		g.enc=enc+(i*292);
		decode_sector(&g);
		_if(2352!=fwrite(sector, 1, 2352, fout), "fwrite sector failed");
	}

	_if((0!=strcmp(infile,"-"))&&(0!=fclose(fin)), "fclose input failed");
	_if((0!=strcmp(outfile,"-"))&&(0!=fclose(fout)), "fclose output failed");
	if(enc)
		free(enc);
}

void bin2ybe(char *infile, char* outfile){
	char *ybe="YBE";
	FILE *fin, *fout;
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

	_if(!(fout=(strcmp(outfile, "-")==0)?stdout:fopen(outfile, "wb")), "Output stream cannot be NULL");
	_if(4!=fwrite(ybe, 1, 4, fout), "fwrite magic failed");
	put32lsb(tmp, sector_cnt);
	_if(4!=fwrite(tmp, 1, 4, fout), "fwrite sector count failed");

	if(crunch && !encoding_written && (g.cnt_conformant==g.cnt_total)){//"perfect" encode method
		for(i=0;i<4;++i){
			if(g.cnt_mode[i])
				break;
		}
		if(g.cnt_mode[i]==g.cnt_total){//input is perfect
			crunch=i+1;
			_if(1!=fwrite(&crunch, 1, 1, fout), "fwrite encoding failed");
			encoding_written=1;
		}
	}
	if(crunch && !encoding_written){//try different encoding forms TODO
	}
	if(!encoding_written){//"raw" encode method
		crunch=0;
		_if(1!=fwrite(&crunch, 1, 1, fout), "fwrite encoding type failed");
		for(i=0;i<sector_cnt;++i)
			_if(yb_type_to_enc_len(enc[i*292])!=fwrite(enc+(i*292), 1, yb_type_to_enc_len(enc[i*292]), fout), "fwrite encoding failed");
	}

	for(i=0;i<sector_cnt;++i)
		_if(yb_type_to_data_len(enc[i*292])!=fwrite(sector+(i*2352)+yb_type_to_data_loc(enc[i*292]), 1, yb_type_to_data_len(enc[i*292]), fout), "fwrite data failed");

	stats_encode(&g);
	_if((0!=strcmp(outfile,"-"))&&(0!=fclose(fout)), "fclose output failed");
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

_Bool str_ends_with(char *str, char *end){
	return (strlen(str)>=strlen(end)) && (strcmp(str+strlen(str)-strlen(end), end)==0);
}

void help(){
	fprintf(stderr,  "ybe v0.1.1\n\nEncode:\n ybe src.bin\n ybe src.bin dest.ybe\n ybe e src.bin dest.ybe\n\n"
		"Decode:\n unybe src.ybe\n unybe src.ybe dest.bin\n ybe d src.ybe dest.bin\n\n"
		"- can take the place of src/dest to pipe with stdin/stdout\n\n");
}

int main(int argc, char *argv[]){
	char *in, *out=NULL;
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
	else if(argc==3)//ybe src dest || unybe src dest
		out=argv[2];
	else if(argc==4){//ybe e src dest || ybe d src dest
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
