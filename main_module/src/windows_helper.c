#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "windows_helper.h"

void win_foreach_process( void( *fn_callback )( PROCESSENTRY32 *proc ) ) {
	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( snapshot == INVALID_HANDLE_VALUE ) {
		return;
	}

	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof( PROCESSENTRY32 );
	if ( !Process32First( snapshot, &process ) ) {
		return;
	}

	do {
		fn_callback( &process );
	} while ( Process32Next( snapshot, &process ) );
}

bool win_inject( uint32_t pid, const char *dll_path ) {
	HANDLE process = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE,
								   pid );
	if ( process == NULL ) {
		return false;
	}

	size_t size = strlen( dll_path ) + 1; // + 1 for '\0'

	void *buffer = VirtualAllocEx( process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( buffer == NULL ) {
		return false;
	}

	if ( !WriteProcessMemory( process, buffer, dll_path, size, NULL ) ) {
		return false;
	}

	HANDLE thread = CreateRemoteThread( process, NULL, 0, LoadLibraryA, buffer, 0, NULL );
	if ( thread == NULL ) {
		return false;
	}

	WaitForSingleObject( thread, INFINITE );

	CloseHandle( thread );
	VirtualFreeEx( process, buffer, 0, MEM_RELEASE );
	CloseHandle( process );
	return true;
}