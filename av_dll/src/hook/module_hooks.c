#include <common.h>

bool is_syscall_stub( const uint8_t *func ) {
	return func[ 0 ] == 0x4C && func[ 1 ] == 0x8B && func[ 2 ] == 0xD1 && func[ 3 ] == 0xB8 && func[ 0x12 ] == 0x0F && func[ 0x13 ] == 0x05;
}

char *get_name( uint8_t *module, IMAGE_EXPORT_DIRECTORY *export, uint32_t i ) {
	uint32_t *name_rvas = ( uint32_t * )( module + export->AddressOfNames );
	return module + name_rvas[ i ];
}

void module_hook( uint8_t *module, bool check_syscalls, void( *fn_hook )( char *function_name, void *fn, void *param_1 ) ) {
	IMAGE_DOS_HEADER *dos = ( IMAGE_DOS_HEADER * )( module );
	IMAGE_NT_HEADERS *nt = ( IMAGE_NT_HEADERS * )( module + dos->e_lfanew );

	IMAGE_EXPORT_DIRECTORY *export = ( IMAGE_EXPORT_DIRECTORY * )( module + nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
	uint16_t *ordinals = ( uint16_t * )( module + export->AddressOfNameOrdinals );
	uint32_t *funcs = ( uint32_t * )( module + export->AddressOfFunctions );
	for ( uint32_t name_index = 0; name_index < export->NumberOfNames; name_index++ ) {
		char *name = get_name( module, export, name_index );
		uint8_t *func = module + funcs[ ordinals[ name_index ] ];

		if ( check_syscalls && !is_syscall_stub( func ) ) {
			continue;
		}

		hook_create( func, fn_hook, name );
	}
}
