#include <common.h>

HMODULE win_get_module_base( uintptr_t address ) {
	PEB *peb = NtCurrentTeb( )->ProcessEnvironmentBlock;
	PEB_LDR_DATA *ldr = peb->Ldr;

	LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
	LIST_ENTRY *curr = head;

	while ( true ) {
		curr = curr->Flink;
		if ( curr == head ) {
			return NULL;
		}

		LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD( curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

		uint32_t size_of_image = *( uint32_t * )( ( uintptr_t )( entry ) + 0x40 );
		uintptr_t base = ( uintptr_t )( entry->DllBase );
		uintptr_t end = base + size_of_image;

		if ( address >= base && address < end ) {
			return entry->DllBase;
		}

	}
}

bool win_is_in_module( uint8_t *ptr, uint8_t *module ) {
	if ( module == NULL ) {
		return false;
	}

	if ( ptr < module ) {
		return false;
	}

	if ( ptr > ( module + pe_get_image_size( module ) ) ) {
		return false;
	}

	return true;
}

size_t win_get_page_size( ) {
	SYSTEM_INFO sys_info = { 0 };
	GetSystemInfo( &sys_info );
	return sys_info.dwPageSize;
}

bool win_is_syscall( uint8_t *ptr ) {
	// CD 2E = int 0x2E
	// 0F 05 = syscall
	
	if ( ptr[ 0 ] == 0xCD && ptr[ 1 ] == 0x3E ) { // int 0x3E
		return true;
	}

	if ( ptr[ 0 ] == 0x0F && ptr[ 1 ] == 0x05 ) { // syscall
		return true;
	}
	return false;
}
