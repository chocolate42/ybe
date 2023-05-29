## Format

All multi-byte integers are little endian

header{
	uint8_t[4] magic; // "YBE\0"
	uint32_t sector_count;
	uint8_t crunch; //Defines how the sector modelling is stored
};

raw_sector_encoding{
	uint8_t type; //type byte encoding the type of the sector and flags for which elements are unmodelled
	uint8_t *unmodelled; //unmodelled elements in the order they appear in the sector
}

file_format{
	header;
	uint8_t *modelling; //varies based on crunch type
	uint8_t *data; //All data sections concatenated in order
}

Crunch byte could double as a version byte for any breaking change beyond it, not just adding new encoding types. Decoder always exits on unrecognised crunch byte.

## Encoding types

* Raw: crunch=0 A raw_sector_encoding for every sector, the fallback if a more compact form isn't found
* Perfect: crunch=1..4 The entire image consists of only one sector type and every non-data element is perfectly modelled. 1=M1 2=M2F1 3=M2F2 4=RAW

## Implementation details

	* Sectors are encoded as one of 4 types: M1, M2F1, M2F2, RAW
	* A sector is determined to be mode 1 if sync and mode are correct
	* A sector is determined to be M2F1 or M2F2 if:
		* Sync and mode are correct
		* The subheader is correctly repeated
		* F1/F2 is determined by the form bit in the subheader
	* A sector is raw otherwise, mostly audio but also intentionally corrupt sectors
		or rare sector types like mode0

## Sector byte type format

```
Type bits
xascpqtt
```

When a flag is set it means the section could not be modelled

x: unused flag
a: address flag
s: sub/intermediate flag
c: EDC flag
p: ECC P flag
q: ECC Q flag
tt: Sector type. 0..3 M1/M2F1/M2F2/RAW
