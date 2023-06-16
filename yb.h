#ifndef YELLOW_BOOK_ENCODING
#define YELLOW_BOOK_ENCODING

#include <stddef.h>
#include <stdint.h>

/* Important constants */
enum{YB_TYPE_M1, YB_TYPE_M2F1, YB_TYPE_M2F2, YB_TYPE_RAW};
enum{YB_ADD=64, YB_SUB=32, YB_EDC=16, YB_ECCP=8, YB_ECCQ=4};

typedef struct{
	uint8_t *data, *enc, *sector;/*source/sink for data/enc/raw sector*/
	uint8_t add_scratch[3];/* Scratch space to convert integer address to BCD format */
	size_t data_cnt, enc_cnt;/* data and enc lengths of current sector encode/decode */
	uint32_t sector_address;/* address, typically incremented from 150 */
	/* counters for stats */
	uint32_t cnt_mode[4];
	uint32_t cnt_dadd, cnt_deccp, cnt_deccq, cnt_dedc, cnt_dint, cnt_dsub;
	uint32_t cnt_conformant, cnt_total;
	//only used if YB_COUNT_ZERO is defined. This way is cleaner to implement
	uint32_t cnt_zero_add, cnt_zero_sub, cnt_zero_edc, cnt_zero_eccp, cnt_zero_eccq;
} yb;

/* encode/decode a sector with an appropriately prepared struct */
void decode_sector(yb *g);
size_t encode_sector(yb *g);

/* Determine things from the type byte */
int yb_type_to_data_len(uint8_t type);
int yb_type_to_data_loc(uint8_t type);
int yb_type_to_enc_len(uint8_t type);

size_t memcpy_cnt(void *dest, const void *src, size_t n);

/* Expose ECM functions called externally */
void eccedc_init(void);
uint32_t get32lsb(const uint8_t* src);
void put32lsb(uint8_t* dest, uint32_t value);

#endif
