#include <common.h>

HANDLE h_rwx_veh = { 0 };

// A list of regions that were RWX and are protected to R-X
struct protected_rwx {
	uint8_t *begin;
	size_t size;
};

// struct protected_rwx
struct vec rwx_regions = { 0 };

void found_rwx( MEMORY_BASIC_INFORMATION *mbi ) {
	struct protected_rwx rwx = { 0 };
	rwx.begin = mbi->BaseAddress;
	rwx.size  = mbi->RegionSize;
	vec_push( &rwx_regions, rwx );

	log_info( "Found RWX region at %p, 0x%llx bytes long\n"
			  " -> protecting RWX -> R-X", mbi->BaseAddress, mbi->RegionSize );

	DWORD old_protect = { 0 };
	if ( VirtualProtect( rwx.begin, rwx.size, PAGE_EXECUTE_READ, &old_protect ) == FALSE ) {
		log_error( "Can't RWX -> R-X (%d)", GetLastError( ) );
		MessageBox( NULL, "Can't protect RWX", "av!ds_scan_all_reg...->rwx", MB_ICONERROR | MB_OK );
		ExitProcess( EXIT_FAILURE );
	}
}

bool is_region_protected( uint8_t *address ) {
	for ( uint32_t index = 0; index < vec_len( &rwx_regions, struct protected_rwx ); index++ ) {
		struct protected_rwx rwx = { 0 };
		vec_get( &rwx_regions, struct protected_rwx, index, &rwx );
		
		uint8_t *begin = rwx.begin;
		uint8_t *end   = begin + rwx.size;

		if ( address >= begin && address < end ) {
			return true;
		}
	}

	return false;
}

LONG NTAPI rwx_veh( EXCEPTION_POINTERS *info ) {
	if ( info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ) {
		log_info( "rwx_veh: not EAV" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if ( !is_region_protected( info->ExceptionRecord->ExceptionAddress ) ) {
		log_info( "rwx_veh: !is_region_protected( )" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	log_error( "rwx_veh: Write to [ ( RWX ) -> ( R-X ) ] protected region (%p)", info->ExceptionRecord->ExceptionAddress );
	MessageBox( NULL, "Write to former RWX region", "av!rwx_veh", MB_ICONERROR | MB_OK );
	ExitProcess( EXIT_FAILURE );
}

void rwx_detect( ) {
	bool has_rwx = false;

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	uint8_t *ptr = NULL;

	while ( true ) {
		size_t size = VirtualQuery( ptr, &mbi, sizeof( mbi ) );

		if ( size == 0 ) {
			break;
		}

		ptr += mbi.RegionSize;

		if ( mbi.State & MEM_FREE ) {
			continue;
		}

		bool rwx = mbi.Protect == PAGE_EXECUTE_READWRITE;
		if ( rwx ) {
			has_rwx = true;
			found_rwx( &mbi );
		}
	}

	// No point adding a VEH if there isn't anything to handle
	if ( !has_rwx ) {
		return;
	}

	h_rwx_veh = AddVectoredExceptionHandler( TRUE, rwx_veh );
}
void rwx_destroy( ) {
	if ( h_rwx_veh ) {
		RemoveVectoredExceptionHandler( h_rwx_veh );
	}

	for ( uint32_t index = 0; index < vec_len( &rwx_regions, struct protected_rwx ); index++ ) {
		struct protected_rwx rwx = { 0 };
		vec_get( &rwx_regions, struct protected_rwx, index, &rwx );

		assert( rwx.begin );
		
		DWORD old_protect = { 0 };
		VirtualProtect( rwx.begin, rwx.size, PAGE_EXECUTE_READWRITE, &old_protect );
	}
}
