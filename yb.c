#include "yb.h"
#ifdef YB_MIN
static void memcpy(uint8_t *dest, const uint8_t *src, size_t n){
	size_t i;
	for(i=0;i<n;++i)
		dest[i]=src[i];
}
static int memcmp(const uint8_t *s1, const uint8_t *s2, size_t n){
	size_t i;
	for(i=0;i<n;++i){
		if(s1[i]!=s2[i])
			return 1;
	}
	return 0;
}
#else
#include <string.h>
#endif


/* ECC generation taken from ECM */
#include "ecm_code.c"

/* Convenient functions to treat P and Q separately without scattering magic numbers too far */
static inline int8_t ecc_checksectorp(const uint8_t *address, const uint8_t *data, const uint8_t *ecc){
	return ecc_checkpq(address, data, 86, 24,  2, 86, ecc);
}
static inline int8_t ecc_checksectorq(const uint8_t *address, const uint8_t *data, const uint8_t *ecc){
	return ecc_checkpq(address, data, 52, 43, 86, 88, ecc + 0xAC);
}
static inline void ecc_writesectorp(const uint8_t *address, const uint8_t *data, uint8_t *ecc){
	ecc_writepq(address, data, 86, 24,  2, 86, ecc);
}
static inline void ecc_writesectorq(const uint8_t *address, const uint8_t *data, uint8_t *ecc){
	ecc_writepq(address, data, 52, 43, 86, 88, ecc + 0xAC);
}

/*Blank sector for comparison*/
static const uint8_t zeroed_address[4]={0};
/*Contents of predicted subheader data. For M1 this is the expected intermediate {0}*/
static const uint8_t subheader[24]={
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 8, 0, 0, 0, 8, 0,
	0, 0, 0x64, 1, 0, 0, 0x64, 1};
static const uint8_t sync[12]={0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0};

static inline void int_to_bcd(int *i, unsigned char *b){
	*b = ((*i/10)<<4) + *i%10;
}

static inline void sec_to_add(uint32_t *sec, unsigned char *add){
	int m, s, f;
	f=*sec%75;
	m=*sec/(75*60);
	s=(*sec-f-(m*60*75))/75;
	int_to_bcd(&m, add+0);
	int_to_bcd(&s, add+1);
	int_to_bcd(&f, add+2);
}

static inline size_t memcpy_cnt(void *dest, const void *src, size_t n){
	memcpy(dest, src, n);
	return n;
}

void decode_sector(yb *g){
	size_t yb_loc=1;
	int head=g->enc[0];
	if((head&3)==YB_TYPE_RAW){
		g->data_cnt=memcpy_cnt(g->sector, g->data, 2352);
		goto DEC_BYE;
	}

	memcpy(g->sector, sync, 12);
	if(head&YB_ADD)
		yb_loc+=memcpy_cnt(g->sector+12, g->enc+yb_loc, 3);
	else
		sec_to_add(&g->sector_address, g->sector+12);

	if((head&3)==YB_TYPE_M1){
		g->sector[15]=1;
		g->data_cnt=memcpy_cnt(g->sector+16, g->data, 2048);

		if(head&YB_EDC)
			yb_loc+=memcpy_cnt(g->sector+2064, g->enc+yb_loc, 4);
		else
			put32lsb(g->sector+2064, edc_compute(0, g->sector, 0x810));

		if(head&YB_SUB)
			yb_loc+=memcpy_cnt(g->sector+2068, g->enc+yb_loc, 8);
		else
			memcpy(g->sector+2068, subheader+((head&3)*8), 8);

		if(head&YB_ECCP)
			yb_loc+=memcpy_cnt(g->sector+2076, g->enc+yb_loc, 172);
		else
			ecc_writesectorp(g->sector+12, g->sector+16, g->sector+2076);

		if(head&YB_ECCQ)
			yb_loc+=memcpy_cnt(g->sector+2248, g->enc+yb_loc, 104);
		else
			ecc_writesectorq(g->sector+12, g->sector+16, g->sector+2076);
		goto DEC_BYE;
	}

	g->sector[15]=2;
	if(head&YB_SUB){
		memcpy(g->sector+16, g->enc+yb_loc, 4);
		yb_loc+=memcpy_cnt(g->sector+20, g->enc+yb_loc, 4);
	}
	else
		memcpy(g->sector+16, subheader+((head&3)*8), 8);

	if((head&3)==YB_TYPE_M2F1){
		g->data_cnt=memcpy_cnt(g->sector+24, g->data, 2048);

		if(head&YB_EDC)
			yb_loc+=memcpy_cnt(g->sector+2072, g->enc+yb_loc, 4);
		else
			put32lsb(g->sector+2072, edc_compute(0, g->sector+16, 2056));

		if(head&YB_ECCP)
			yb_loc+=memcpy_cnt(g->sector+2076, g->enc+yb_loc, 172);
		else
			ecc_writesectorp(zeroed_address, g->sector+16, g->sector+2076);

		if(head&YB_ECCQ)
			yb_loc+=memcpy_cnt(g->sector+2248, g->enc+yb_loc, 104);
		else
			ecc_writesectorq(zeroed_address, g->sector+16, g->sector+2076);
	}
	else{//YB_TYPE_M2F2
		g->data_cnt=memcpy_cnt(g->sector+24, g->data, 2324);

		if(head&YB_EDC)
			yb_loc+=memcpy_cnt(g->sector+2348, g->enc+yb_loc, 4);
		else
			put32lsb(g->sector+2348, edc_compute(0, g->sector+16, 2332));
	}

	DEC_BYE:
	++g->sector_address;
	g->enc_cnt=yb_loc;
}

/*Copy section of a sector and update stats if it cannot be predicted*/
static inline void ecpy(uint8_t *type, uint8_t mask, uint32_t *counter, uint8_t *enc, size_t *enc_loc, uint8_t *cpy, int len){
	(*counter)++;
	(*type)|=mask;
	memcpy(enc+(*enc_loc), cpy, len);
	(*enc_loc)+=len;
}

/* Encode a sector g->sector into g->enc */
size_t encode_sector(yb *g){
	size_t enc_loc=1;
	uint8_t *sec=g->sector, *enc=g->enc, type=0;

	if(memcmp(sync, sec, 12)==0){/* sync present, could be M1/M2F1/M2F2 */
		if(sec[15]==1){/*M1*/
			++g->cnt_mode[YB_TYPE_M1];
			type+=YB_TYPE_M1;

			sec_to_add(&g->sector_address, g->add_scratch);
			if(memcmp(sec+12, g->add_scratch, 3)!=0)
				ecpy(&type, YB_ADD, &g->cnt_dadd, enc, &enc_loc, sec+12, 3);

			g->data=sec+16;
			g->data_cnt=2048;

			if(edc_compute(0, sec, 2064)!=get32lsb(sec + 2064))
				ecpy(&type, YB_EDC, &g->cnt_dedc, enc, &enc_loc, sec+2064, 4);

			if(memcmp(subheader, sec+2068, 8)!=0)
				ecpy(&type, YB_SUB, &g->cnt_dint, enc, &enc_loc, sec+2068, 8);

			if(!ecc_checksectorp(sec+12, sec+16, sec+2076))
				ecpy(&type, YB_ECCP, &g->cnt_deccp, enc, &enc_loc, sec+2076, 172);

			if(!ecc_checksectorq(sec+12, sec+16, sec+2076))
				ecpy(&type, YB_ECCQ, &g->cnt_deccq, enc, &enc_loc, sec+2248, 104);
		}
		else if(sec[15]==2 && memcmp(sec+16, sec+20, 4)==0){
			if(sec[18]&32){/*M2F2*/
				++g->cnt_mode[YB_TYPE_M2F2];
				type+=YB_TYPE_M2F2;

				sec_to_add(&g->sector_address, g->add_scratch);
				if(memcmp(sec+12, g->add_scratch, 3)!=0)
					ecpy(&type, YB_ADD, &g->cnt_dadd, enc, &enc_loc, sec+12, 3);

				if(memcmp(sec+16, subheader+16, 8)!=0)
					ecpy(&type, YB_SUB, &g->cnt_dsub, enc, &enc_loc, sec+16, 4);

				g->data=sec+24;
				g->data_cnt=2324;

				if(edc_compute(0, sec+16, 2332) != get32lsb(sec+2348))
					ecpy(&type, YB_EDC, &g->cnt_dedc, enc, &enc_loc, sec+2348, 4);
			}
			else{/*M2F1*/
				++g->cnt_mode[YB_TYPE_M2F1];
				type+=YB_TYPE_M2F1;

				sec_to_add(&g->sector_address, g->add_scratch);
				if(memcmp(sec+12, g->add_scratch, 3)!=0)
					ecpy(&type, YB_ADD, &g->cnt_dadd, enc, &enc_loc, sec+12, 3);

				if(memcmp(sec+16, subheader+8, 8)!=0)
					ecpy(&type, YB_SUB, &g->cnt_dsub, enc, &enc_loc, sec+16, 4);

				g->data=sec+24;
				g->data_cnt=2048;

				if(edc_compute(0, sec+16, 2056) != get32lsb(sec + 2072))
					ecpy(&type, YB_EDC, &g->cnt_dedc, enc, &enc_loc, sec+2072, 4);

				if(!ecc_checksectorp(zeroed_address, sec+16, sec+2076))
					ecpy(&type, YB_ECCP, &g->cnt_deccp, enc, &enc_loc, sec+2076, 172);

				if(!ecc_checksectorq(zeroed_address, sec+16, sec+2076))
					ecpy(&type, YB_ECCQ, &g->cnt_deccq, enc, &enc_loc, sec+2248, 104);
			}
		}
		else{/* Not M1/M2F1/M2F2, treat as raw */
			++g->cnt_mode[YB_TYPE_RAW];
			type+=YB_TYPE_RAW;
			g->data=sec;
			g->data_cnt=2352;
		}
	}
	else{/* no sync, treat as RAW */
		++g->cnt_mode[YB_TYPE_RAW];
		type+=YB_TYPE_RAW;
		g->data=sec;
		g->data_cnt=2352;
	}

	enc[0]=type;
	g->enc_cnt=enc_loc;

	++g->cnt_total;
	if(enc_loc==1)
		++g->cnt_conformant;
	++g->sector_address;
	return enc_loc;
}

/* Determine length of yb_data from the type byte */
int yb_type_to_data_len(uint8_t type){
	int len[4]={2048, 2048, 2324, 2352};
	return len[type&3];
}

int yb_type_to_data_loc(uint8_t type){
	int loc[4]={16, 24, 24, 0};
	return loc[type&3];
}

/* Determine length of yb_enc from the type byte */
static const uint16_t yb_enc_cnt[128]={
	1,1,1,1,105,105,1,1,173,173,1,1,277,277,1,1,5,5,5,1,109,109,5,1,
	177,177,5,1,281,281,5,1,9,5,5,1,113,109,5,1,181,177,5,1,285,281,5,1,
	13,9,9,1,117,113,9,1,185,181,9,1,289,285,9,1,4,4,4,1,108,108,4,1,
	176,176,4,1,280,280,4,1,8,8,8,1,112,112,8,1,180,180,8,1,284,284,8,1,
	12,8,8,1,116,112,8,1,184,180,8,1,288,284,8,1,16,12,12,1,120,116,12,1,
	188,184,12,1,292,288,12,1
};

int yb_type_to_enc_len(uint8_t type){
	return yb_enc_cnt[type&127];
}
