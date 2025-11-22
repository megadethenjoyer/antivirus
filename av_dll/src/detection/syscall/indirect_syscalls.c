#include <common.h>

bool is_check( uint8_t *func ) {
	const uint8_t start[ ] = {
		0x4C, 0x8B, 0xD1,
		0xB8
	};

	if ( memcmp( func, start, sizeof( start ) ) != 0 ) {
		return false;
	}

	const uint8_t next[ ] = {
		0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,
		0x75, 0x03,
		0x0F, 0x05,
		0xC3,

		0xCD, 0x2E,
		0xC3
	};

	return memcmp( func + 8, next, sizeof( next ) ) == 0;
}

void hook_stub( uint8_t *stub ) {
	if ( !stub ) {
		return;
	}
}
void is_init( HMODULE ntdll ) {
	//for ( int index = 0; index < sizeof( syscalls ) / sizeof( *syscalls ); index++ ) {
		//hook_stub( GetProcAddress( ntdll, syscalls[ index ] ) );
	//}
}