#include "yb.h"
#include "ybcrunch.h"
#include "ybe_common.h"
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void stats_encode(yb *g){
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

static void ybe2bin(char *infile, char* outfile){
	FILE *fin=NULL, *fout=NULL;
	int stride;
	uint8_t data[2352], *enc=NULL, sector[2352];
	uint32_t i, sector_cnt;
	yb g={0};

	_if(!(fin=(strcmp(infile, "-")==0)?stdin:fopen(infile, "rb")), "Input stream cannot be NULL");
	ybe_read_header(fin, &sector_cnt);
	enc=yb_uncrunch(fin, sector_cnt, &stride);

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

static void bin2ybe(char *infile, char* outfile){
	char *ybe="YBE";
	FILE *fin, *fout=NULL;
	size_t sector_alloc=0, sector_cnt=0, enc_size_tot=0, i, fread_res, enc_crunch_cnt;
	uint8_t *enc=NULL, *enc_crunch=NULL, *sector=NULL, tmp[4];
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

	enc_crunch=yb_crunch(&g, enc, sector_cnt, &enc_crunch_cnt);
	_if(fout&&(enc_crunch_cnt!=fwrite(enc_crunch, 1, enc_crunch_cnt, fout)), "fwrite crunch encoding failed");
	free(enc_crunch);

	for(i=0;i<sector_cnt;++i)
		_if(fout&&(yb_type_to_data_len(enc[i*292])!=fwrite(sector+(i*2352)+yb_type_to_data_loc(enc[i*292]), 1, yb_type_to_data_len(enc[i*292]), fout)), "fwrite data failed");

	stats_encode(&g);
	_if(fout&&(0!=strcmp(outfile,"-"))&&(0!=fclose(fout)), "fclose output failed");
	if(enc)
		free(enc);
	if(sector)
		free(sector);
}

static char *gen_outpath(char *inpath, int trunc){
	char *outpath;
	_if(!(outpath=malloc(strlen(inpath)+5)), "malloc failed");
	sprintf(outpath, "%s.ybe", inpath);
	outpath[strlen(inpath)+trunc]=0;
	return outpath;
}

static void help(){
	fprintf(stderr,  "ybe v0.2.2\n\nEncode:\n ybe src.bin\n ybe src.bin dest.ybe\n ybe e src.bin dest.ybe\n\n"
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
	if(out)
		fprintf(stderr, "%scode '%s' to '%s'\n", enc?"En":"De", in, out);
	else
		fprintf(stderr, "%scode '%s'\n", enc?"En":"De", in);
	func[enc](in, out);
	if(argc==2)
		free(out);

	return 0;
}
