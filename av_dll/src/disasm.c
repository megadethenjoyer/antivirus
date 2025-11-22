#include <common.h>

size_t disasm_find_good_size( size_t min_size, uint8_t *code ) {
	INSTRUX ix = { 0 };

	NDSTATUS status = NdDecode( &ix, code, ND_CODE_64, ND_DATA_64 );
	if ( !ND_SUCCESS( status ) ) {
		return 0;
	}

	size_t length = ix.Length;

	while ( length < min_size ) {
		status = NdDecode( &ix, code + length, ND_CODE_64, ND_DATA_64 );
		if ( !ND_SUCCESS( status ) ) {
			return 0;
		}
		length += ix.Length;
	}

	return length;
}