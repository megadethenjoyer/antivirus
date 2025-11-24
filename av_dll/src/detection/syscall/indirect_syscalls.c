#include <common.h>
#include <smipc.h>
#include <assert.h>

void *g_detour = NULL;

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

	if ( !is_check( stub ) ) {
		return;
	}

	DWORD old_protect = 0;
	VirtualProtect( stub, 21, PAGE_EXECUTE_READWRITE, &old_protect );
	uint8_t replace[ ] = {
		0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, // mov r10, detour
		0x41, 0xFF, 0xE2					// jmp r10
	};

	*( void ** )( replace + 2 ) = g_detour;
	memcpy( stub + 8, replace, sizeof( replace ) );
	VirtualProtect( stub, 21, old_protect, &old_protect );
}

void hook_module( void *base ) {
	// TODO: maybe add some checks?
	IMAGE_DOS_HEADER *dos = base;
	IMAGE_NT_HEADERS *nt = ( uint8_t * )( base ) + dos->e_lfanew;

	IMAGE_DATA_DIRECTORY export = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
	IMAGE_EXPORT_DIRECTORY *export_dir = ( uint8_t * )( base ) + export.VirtualAddress;
	uint32_t *func_arr = ( uint8_t * )( base )+export_dir->AddressOfFunctions;
	for ( int i = 0; i < export_dir->NumberOfFunctions; i++ ) {
		if ( !(i % 20 ) ){
		log_info( "Hook %d", i );
		}
		uint32_t func_rva = func_arr[ export_dir->Base + i ];
		hook_stub( ( uint8_t * )( base ) + func_rva );
	}
}

void send_init( ) {
	buf->init.exec_stub = VirtualAlloc( NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	buf->init.pid = GetCurrentProcessId( );
	buf->init.sb = buf;

	buf->type = msg_init;

	while ( buf->type != msg_done ) {
		YieldProcessor( );
	}
}

void suspend_all_threads(  ) {
	HANDLE h = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	THREADENTRY32 t = { 0 };
	t.dwSize = sizeof( t );
	Thread32First( h, &t );

	while ( 1 ) {
		if ( !Thread32Next( h, &t ) ) {
			break;
		}

		if ( t.th32OwnerProcessID != GetCurrentProcessId() ) {
			continue;
		}

		if ( t.th32ThreadID == GetCurrentThreadId( ) ) {
			continue;
		}

		
		HANDLE th = OpenThread( THREAD_ALL_ACCESS, 0, t.th32ThreadID );
		SuspendThread( th );
		CloseHandle( th );
	}

	CloseHandle( h );

}
void resume( ) {
	HANDLE h = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	THREADENTRY32 t = { 0 };
	t.dwSize = sizeof( t );
	Thread32First( h, &t );

	while ( 1 ) {
		if ( !Thread32Next( h, &t ) ) {
			break;
		}


		if ( t.th32OwnerProcessID != GetCurrentProcessId() ) {
			continue;
		}

		if ( t.th32ThreadID == GetCurrentThreadId( ) ) {
			continue;
		}

		
		HANDLE th = OpenThread( THREAD_ALL_ACCESS, 0, t.th32ThreadID );
		ResumeThread( th );
		CloseHandle( th );
	}

	CloseHandle( h );
}

void is_init( HMODULE ntdll ) {
	log_info( "Sending init." );
	send_init( );
	log_info( "Init done." );


	suspend_all_threads( );
	PEB *peb = ( PEB * )__readgsqword( 0x60 );
	PEB_LDR_DATA *ldr = peb->Ldr;

	LDR_DATA_TABLE_ENTRY *head = &ldr->InMemoryOrderModuleList;
	LDR_DATA_TABLE_ENTRY *curr = head;
	curr = CONTAINING_RECORD( curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

	g_detour = VirtualAlloc( NULL, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	uint8_t detour[ ] = {
		0x50,											// push rax
		0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,				// mov r10, (buf)
		0x65, 0x8B, 0x04, 0x25, 0x48, 0x00, 0x00, 0x00, // mov eax, gs:[0x48] (TID)
		0x41, 0x89, 0x42, 0x04,							// mov dword ptr [r10 + 0x4], eax
		0x58,											// pop rax

		0x41, 0xC7, 0x02, 0x02, 0x00, 0x00, 0x00,	// mov dword ptr [r10], 2 (msg_syscall)
		// .wait:
		0x41, 0x83, 0x3A, 0x03,						// cmp dword ptr [r10], 3 (msg_done)
		0x75, 0xFA,									// jne .wait
		0xC3										// ret
	};

	*( void ** )( detour + 3 ) = buf;
	for ( int i = 0; i < sizeof( detour ); i++ ) {
		volatile uint8_t *ptr = ( uint8_t * )( g_detour );
		uint8_t tr = detour[ i ];
		ptr[ i ] = tr;
	}
	// memcpy( g_detour, detour, sizeof( detour ) );
	DWORD old_prot = 0;
	VirtualProtect( g_detour, 128, PAGE_EXECUTE_READ, &old_prot );

	while ( 1 ) {
		curr = curr->InMemoryOrderLinks.Flink;

		if ( curr == head ) {
			log_info( "curr == head" );
			break;
		}

		curr = CONTAINING_RECORD( curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
	

		log_info( "hook %ws", curr->FullDllName.Buffer );
		hook_module( curr->DllBase );


	}

	resume( );

	//for ( int index = 0; index < sizeof( syscalls ) / sizeof( *syscalls ); index++ ) {
		//hook_stub( GetProcAddress( ntdll, syscalls[ index ] ) );
	//}
}