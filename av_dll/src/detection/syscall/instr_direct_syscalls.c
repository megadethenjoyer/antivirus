#include <common.h>

HANDLE g_inds_veh = { 0 };

// A list of overwritten instructions ( uint8_t * )
struct vec overwritten_instructions = { 0 };

bool is_instruction_overwritten( uint8_t *instr ) {
	for ( uint32_t index = 0; index < vec_len( &overwritten_instructions, uint8_t * ); index++ ) {
		uint8_t *overwritten_instr = { 0 };
		vec_get( &overwritten_instructions, uint8_t *, index, &overwritten_instr );

		if ( overwritten_instr == instr ) {
			return true;
		}
	}

	return false;
}

DWORD WINAPI inds_veh( EXCEPTION_POINTERS *info ) {
	log_info( "inds_veh( )" );

	if ( info->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT ) {
		log_info( " -> not BP\n" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if ( !is_instruction_overwritten( info->ExceptionRecord->ExceptionAddress ) ) {
		log_info( " -> not OW\n" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	log_error( " -> !!" );
	log_info(  " -> instr %p", info->ExceptionRecord->ExceptionAddress );

	MessageBox( NULL, "Caught direct syscall", "av_dll!inds_veh->ow", MB_OK | MB_ICONERROR );
	ExitProcess( EXIT_FAILURE );

}

void inds_init( ) {
	g_inds_veh = AddVectoredExceptionHandler( TRUE, inds_veh );
}

bool is_actual_instruction( uint8_t *instr ) {
	HMODULE base = win_get_module_base( ( uintptr_t )( instr ) );
	assert( base );
	if ( base == NULL ) {
		return false;
	}

	uint8_t *func = pe_get_function_base( base, instr );
	if ( func == NULL ) {
		//! this is likely because of masm
		//  maybe provide a setting to block this?
		//  for now just let hwbpds handle it
		log_error( "is_actual_instruction: found syscall instr %p and couldn't find pdata func", instr );
		return false;
	}

	// Check for ntdll-ish syscall stub
	// TODO: this is a hacky place to put it
	if ( is_check( func ) ) {
		return false;
	}

	size_t instr_offset = ( ( uintptr_t )( instr ) ) - ( ( uintptr_t )( func ) );

	size_t good_size = disasm_find_good_size( instr_offset, func );

	return good_size == instr_offset;

}

void inds_scan_region( uint8_t *ptr, size_t size ) {
	log_info( "inds_scan_region( %p, %llx )", ptr, size );
	// ( size - 1 ) because `syscall` is 2 bytes
	for ( uint32_t i = 0; i < ( size - 1 ); i++ ) {
		uint8_t *instr = ptr + i;

		if ( !win_is_syscall( instr ) ) {
			continue;
		}

		if ( !is_actual_instruction( instr ) ) {
			continue;
		}

		log_info( "inds_scan_region: detect actual instr %p", instr );

		vec_push( &overwritten_instructions, instr );

		DWORD old_protect = { 0 };
		VirtualProtect( instr, 2, PAGE_READWRITE, &old_protect );

		instr[ 0 ] = 0xCC;
		instr[ 1 ] = 0xCC;

		VirtualProtect( instr, 2, old_protect, &old_protect );
	}
}

void inds_scan_all_regions( ) {
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	uint8_t *ptr = NULL;

	while ( true ) {
		size_t size = VirtualQuery( ptr, &mbi, sizeof( mbi ) );

		if ( size == 0 ) {
			return;
		}

		ptr += mbi.RegionSize;

		if ( mbi.State & MEM_FREE ) {
			continue;
		}

		if ( !win_is_protect_executable( mbi.Protect ) ) {
			continue;
		}

		if ( av_is_whitelisted( mbi.BaseAddress ) ) {
			continue;
		}

		inds_scan_region( mbi.BaseAddress, mbi.RegionSize );
	}
}

void inds_deinit( ) { }
