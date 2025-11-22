#include <common.h>

// A list of pages that are R-- and contain a DS hook
struct protected_page {
	uintptr_t page;
	DWORD old_protect;
};

// uint8_t*
struct vec hooked_instructions = { 0 };

// struct protected_page
struct vec protected_pages = { 0 };

HANDLE h_ds_veh = { 0 };

uint32_t lock_hook = 0;

bool is_indirect_syscall_stub( uint8_t *stub ) {
	const uint8_t begin[ 4 ] = {
		0x4C, 0x8B, 0xD1, // mov r10, rcx
		0xB8              // mov eax, ?
	};

	if ( memcmp( stub, begin, 4 ) != 0 ) {
		return false;
	}

	const uint8_t middle[ 16 ] = {
		0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, // test byte [0x7FFE0308], 1
		0x75, 0x03,                                     // jnz .int2E_stub
		// .syscall_stub
		0x0F, 0x05, // syscall
		0xC3,       // ret

		// .int2E_stub
		0xCD, 0x2E, // int 0x2E
		0xC3        // ret
	};

	if ( memcmp( stub + 3 + 5, middle, 16 ) != 0 ) {
		return false;
	}

	return true;
}

bool is_indirect_syscall( uint8_t *syscall ) {
	uint8_t *begin_syscall = syscall - 18;
	uint8_t *begin_int2E   = syscall - 18 - 3;

	return is_indirect_syscall_stub( begin_syscall ) ||
		   is_indirect_syscall_stub( begin_int2E   );
}

bool is_page_protected( uintptr_t page ) {
	for ( uint32_t index = 0; index < vec_len( &protected_pages, struct protected_page ); index++ ) {
		struct protected_page protected_page = { 0 };
		vec_get( &protected_pages, struct protected_page, index, &protected_page );
		
		if ( protected_page.page == page ) {
			return true;
		}
	}

	return false;
}

bool is_in_page( uintptr_t ptr, uintptr_t page ) {
	return win_mask_page( ptr ) == page;
}

void find_instructions_in_page( uintptr_t *instructions, uint32_t *instruction_count, uintptr_t page ) {
	for ( uint32_t index = 0; index < vec_len( &hooked_instructions, uintptr_t ); index++ ) {
		// Get instruction
		uintptr_t hooked_instruction = { 0 };
		vec_get( &hooked_instructions, uintptr_t , index, &hooked_instruction );

		// Not relevant - isn't in the same page
		if ( !is_in_page( hooked_instruction, page ) ) {
			continue;
		}

		( *instruction_count )++;

		if ( *instruction_count > 4 ) {
			continue;
		}

		instructions[ *instruction_count - 1 ] = hooked_instruction;
	}
}

DWORD protect_page( uintptr_t ptr, DWORD protect ) {
	DWORD old_protect = { 0 };
	BOOL result = VirtualProtect( ( void * )( win_mask_page( ptr ) ), win_get_page_size( ), protect, &old_protect );

	return old_protect;
}

// This function sets the debug registers of a thread's context
// according to current free ones and required ones.
void patch_thread_context( CONTEXT *context, uintptr_t *instructions, uint32_t instruction_count ) {
	uint32_t left_instructions = instruction_count;
	if ( left_instructions > 4 ) {
		left_instructions = 4;
	}
	
	// Free debug registers
	uint32_t free_drs = 0;

	uintptr_t *drs[ 4 ] = { &context->Dr0, &context->Dr1, &context->Dr2, &context->Dr3 };

	for ( int index = 0; index < 4; index++ ) {
		if ( *drs[ index ] == 0 ) {
			continue;
		}

		protect_page( *drs[ index ], PAGE_READONLY );
		*drs[ index ] = 0;
	}

	// Fill DRs with new values
	for ( int index = 0; index < 4; index++ ) {
		if ( instructions[ index ] == 0 ) {
			continue;
		}

		*drs[ index ] = instructions[ index ];

		context->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
		// enable execution bit for index
		context->Dr7 |= ( 3ull << index );
	}
}

void hit_bp( EXCEPTION_POINTERS *info ) {
	log_info( "Hit BP @ %p", info->ExceptionRecord->ExceptionAddress );
	
	if ( win_is_syscall( info->ExceptionRecord->ExceptionAddress ) ) {
		// TODO: rare edgecase - this might actually be a read and not an execute
		log_error( "that's a syscall" );
		MessageBox( NULL, "Detected direct syscall!", "av!ds_veh->hit_bp", MB_ICONERROR | MB_OK );
		ExitProcess( EXIT_FAILURE );
	}
}

LONG NTAPI hwbpds_veh( EXCEPTION_POINTERS *info ) {
	log_info( "Hit ds_veh" );
	if ( info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP || info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT ) {
		hit_bp( info );
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if ( info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ) {
		log_info( "ds_veh: Not EAV" );
		return EXCEPTION_CONTINUE_SEARCH;
	}


	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if ( VirtualQuery( info->ExceptionRecord->ExceptionAddress, &mbi, sizeof( mbi ) ) != sizeof( mbi ) ) {
		log_info( "ds_veh: VQ fail" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if ( mbi.State == MEM_FREE ) {
		log_info( "ds_veh: Is MEM_FREE" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if ( mbi.Protect == PAGE_NOACCESS ) {
		log_info( "ds_veh: no access" );
		return EXCEPTION_CONTINUE_SEARCH;
	}

	uint8_t *address = ( uint8_t * )( info->ExceptionRecord->ExceptionAddress );
	uintptr_t page   = win_mask_page( address );

	if ( !is_page_protected( page ) ) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	LOCK( &lock_hook );

	log_ok( "good (%p) - now, proceed onto DR hooking", address );

	int instruction_count = 0;
	uintptr_t instructions[ 4 ] = { 0 };

	find_instructions_in_page( instructions, &instruction_count, page );

	if ( instruction_count > 4 ) {
		log_error( "More than 4 instructions in page (ds_veh) -> %d", instruction_count );
		int mb_response = MessageBox( NULL, "More than 4 instructions in page\nExit?", "av!hwbpds_veh", MB_YESNO | MB_ICONERROR );
		if ( mb_response == IDYES ) {
			ExitProcess( EXIT_FAILURE );
		}
	}

	patch_thread_context( info->ContextRecord, instructions, instruction_count );

	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	THREADENTRY32 thread_entry = { 0 };
	thread_entry.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( snapshot, &thread_entry ) ) {
		log_error( "Can't Thread32First (%d)", GetLastError( ) );
		MessageBox( NULL, "Can't iterate threads", "av!hwbpds_veh:Thread32First", MB_ICONERROR | MB_OK );
		ExitProcess( EXIT_FAILURE );
	}
	do {
		if ( thread_entry.th32OwnerProcessID != GetCurrentProcessId( ) ) {
			continue;
		}

		bool self = thread_entry.th32ThreadID == GetCurrentThreadId( );
		if ( self ) {
			continue;
		}

		HANDLE thread = OpenThread( THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_entry.th32ThreadID );
		// Thread already exited.
		if ( !thread && GetLastError( ) == ERROR_INVALID_PARAMETER ) {
			continue;
		}
		if ( !thread ) {
			log_error( "Couldn't open thread %d for DS hook / DrN (%d)", thread_entry.th32ThreadID, GetLastError( ) );
			MessageBox( NULL, "Can't hook for DS detection", "av!hwbpds_veh:OpenThread", MB_ICONERROR | MB_OK );
			ExitProcess( EXIT_FAILURE );
		}


		if ( SuspendThread( thread ) == ( DWORD )( -1 ) ) {
			log_error( "Can't suspend (%d)", GetLastError( ) );
			MessageBox( NULL, "Can't suspend", "av!hwbpds_veh:SuspendThread", MB_ICONERROR | MB_OK );
			ExitProcess( EXIT_FAILURE );
		}

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if ( !GetThreadContext( thread, &context ) ) {
			log_error( "Can't get context (%d)", GetLastError( ) );
			MessageBox( NULL, "Can't get context of thread", "av!hwbpds_veh:GetThreadContext", MB_ICONERROR | MB_OK );
			ExitProcess( EXIT_FAILURE );
		}

		patch_thread_context( &context, instructions, instruction_count );

		if ( !SetThreadContext( thread, &context ) ) {
			log_error( "Can't set context (%d)", GetLastError( ) );
			MessageBox( NULL, "Can't set context of thread", "av!ds_veh:SetThreadContext", MB_ICONERROR | MB_OK );
			ExitProcess( EXIT_FAILURE );
		}

		if ( ResumeThread( thread ) == ( DWORD )( -1 ) ) {
			log_error( "Can't resume (%d)", GetLastError( ) );
			MessageBox( NULL, "Can't resume", "av!hwbpds_veh:ResumeThread", MB_ICONERROR | MB_OK );
			ExitProcess( EXIT_FAILURE );
		}


		CloseHandle( thread );
	} while ( Thread32Next( snapshot, &thread_entry ) );

	CloseHandle( snapshot );

	log_info( "protect page %llx R-X", page );
	protect_page( page, PAGE_EXECUTE_READ );

	UNLOCK( &lock_hook );

	return EXCEPTION_CONTINUE_EXECUTION;
}


void hwbpds_init( ) {
	h_ds_veh = AddVectoredExceptionHandler( TRUE, hwbpds_veh );
}

void hwbpds_scan_region( uint8_t *ptr, size_t size ) {
	log_info( "ds_scan_region( %p, %llx )", ptr, size );

	uintptr_t last_page = 0;

	// ( size - 1 ) because `syscall` is 2 bytes
	for ( uint32_t i = 0; i < ( size - 1 ); i++ ) {
		uint8_t *instr = ptr + i;

		if ( !win_is_syscall( instr ) ) {
			continue;
		}

		uintptr_t this_page = win_mask_page( instr );
		if ( last_page != this_page ) {
			last_page = this_page;

			struct protected_page protected_page = { 0 };

			DWORD old_protect = protect_page( this_page, PAGE_READONLY );

			protected_page.page	       = this_page;
			protected_page.old_protect = old_protect;

			vec_push( &protected_pages, protected_page );
		}

		vec_push( &hooked_instructions, instr );
	}
}


void hwbpds_scan_all_regions( ) {
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

		hwbpds_scan_region( mbi.BaseAddress, mbi.RegionSize );
	}
}

void hwbpds_deinit( ) {
	//RemoveVectoredExceptionHandler( h_ds_veh );
	
	for ( uint32_t index = 0; index < vec_len( &protected_pages, struct protected_page ); index++ ) {
		struct protected_page protected_page = { 0 };
		vec_get( &hooked_instructions, struct protected_page, index, &protected_page );

		protect_page( protected_page.page, protected_page.old_protect );
	}

	vec_free( &protected_pages );
	vec_free( &hooked_instructions );
}
