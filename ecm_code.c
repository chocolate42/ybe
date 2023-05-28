////////////////////////////////////////////////////////////////////////////////
//
#define TITLE "ecm - Encoder/decoder for Error Code Modeler format"
#define COPYR "Copyright (C) 2002-2011 Neill Corlett"
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
//
// Sector types
//
// Mode 1
// -----------------------------------------------------
//        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// 0000h 00 FF FF FF FF FF FF FF FF FF FF 00 [-ADDR-] 01
// 0010h [---DATA...
// ...
// 0800h                                     ...DATA---]
// 0810h [---EDC---] 00 00 00 00 00 00 00 00 [---ECC...
// ...
// 0920h                                      ...ECC---]
// -----------------------------------------------------
//
// Mode 2 (XA), form 1
// -----------------------------------------------------
//        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// 0000h 00 FF FF FF FF FF FF FF FF FF FF 00 [-ADDR-] 02
// 0010h [--FLAGS--] [--FLAGS--] [---DATA...
// ...
// 0810h             ...DATA---] [---EDC---] [---ECC...
// ...
// 0920h                                      ...ECC---]
// -----------------------------------------------------
//
// Mode 2 (XA), form 2
// -----------------------------------------------------
//        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// 0000h 00 FF FF FF FF FF FF FF FF FF FF 00 [-ADDR-] 02
// 0010h [--FLAGS--] [--FLAGS--] [---DATA...
// ...
// 0920h                         ...DATA---] [---EDC---]
// -----------------------------------------------------
//
// ADDR:  Sector address, encoded as minutes:seconds:frames in BCD
// FLAGS: Used in Mode 2 (XA) sectors describing the type of sector; repeated
//        twice for redundancy
// DATA:  Area of the sector which contains the actual data itself
// EDC:   Error Detection Code
// ECC:   Error Correction Code
//

////////////////////////////////////////////////////////////////////////////////

uint32_t get32lsb(const uint8_t* src) {
    return
        (((uint32_t)(src[0])) <<  0) |
        (((uint32_t)(src[1])) <<  8) |
        (((uint32_t)(src[2])) << 16) |
        (((uint32_t)(src[3])) << 24);
}

void put32lsb(uint8_t* dest, uint32_t value) {
    dest[0] = (uint8_t)(value      );
    dest[1] = (uint8_t)(value >>  8);
    dest[2] = (uint8_t)(value >> 16);
    dest[3] = (uint8_t)(value >> 24);
}

////////////////////////////////////////////////////////////////////////////////
//
// LUTs used for computing ECC/EDC
//
static uint8_t  ecc_f_lut[256];
static uint8_t  ecc_b_lut[256];
static uint32_t edc_lut  [256];

void eccedc_init(void) {
    size_t i;
    for(i = 0; i < 256; i++) {
        uint32_t edc = i;
        size_t j = (i << 1) ^ (i & 0x80 ? 0x11D : 0);
        ecc_f_lut[i] = j;
        ecc_b_lut[i ^ j] = i;
        for(j = 0; j < 8; j++) {
            edc = (edc >> 1) ^ (edc & 1 ? 0xD8018001 : 0);
        }
        edc_lut[i] = edc;
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Compute EDC for a block
//
static uint32_t edc_compute(
    uint32_t edc,
    const uint8_t* src,
    size_t size
) {
    for(; size; size--) {
        edc = (edc >> 8) ^ edc_lut[(edc ^ (*src++)) & 0xFF];
    }
    return edc;
}

////////////////////////////////////////////////////////////////////////////////
//
// Check ECC block (either P or Q)
// Returns true if the ECC data is an exact match
//
static int8_t ecc_checkpq(
    const uint8_t* address,
    const uint8_t* data,
    size_t major_count,
    size_t minor_count,
    size_t major_mult,
    size_t minor_inc,
    const uint8_t* ecc
) {
    size_t size = major_count * minor_count;
    size_t major;
    for(major = 0; major < major_count; major++) {
        size_t index = (major >> 1) * major_mult + (major & 1);
        uint8_t ecc_a = 0;
        uint8_t ecc_b = 0;
        size_t minor;
        for(minor = 0; minor < minor_count; minor++) {
            uint8_t temp;
            if(index < 4) {
                temp = address[index];
            } else {
                temp = data[index - 4];
            }
            index += minor_inc;
            if(index >= size) { index -= size; }
            ecc_a ^= temp;
            ecc_b ^= temp;
            ecc_a = ecc_f_lut[ecc_a];
        }
        ecc_a = ecc_b_lut[ecc_f_lut[ecc_a] ^ ecc_b];
        if(
            ecc[major              ] != (ecc_a        ) ||
            ecc[major + major_count] != (ecc_a ^ ecc_b)
        ) {
            return 0;
        }
    }
    return 1;
}

//
// Write ECC block (either P or Q)
//
static void ecc_writepq(
    const uint8_t* address,
    const uint8_t* data,
    size_t major_count,
    size_t minor_count,
    size_t major_mult,
    size_t minor_inc,
    uint8_t* ecc
) {
    size_t size = major_count * minor_count;
    size_t major;
    for(major = 0; major < major_count; major++) {
        size_t index = (major >> 1) * major_mult + (major & 1);
        uint8_t ecc_a = 0;
        uint8_t ecc_b = 0;
        size_t minor;
        for(minor = 0; minor < minor_count; minor++) {
            uint8_t temp;
            if(index < 4) {
                temp = address[index];
            } else {
                temp = data[index - 4];
            }
            index += minor_inc;
            if(index >= size) { index -= size; }
            ecc_a ^= temp;
            ecc_b ^= temp;
            ecc_a = ecc_f_lut[ecc_a];
        }
        ecc_a = ecc_b_lut[ecc_f_lut[ecc_a] ^ ecc_b];
        ecc[major              ] = (ecc_a        );
        ecc[major + major_count] = (ecc_a ^ ecc_b);
    }
}
