#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include "windows_helper.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ipc.h"

#define DLL_NAME "av_dll.dll"
#define BUFSIZE ( 1024 )
#define PIPE_NAME ( "\\\\.\\pipe\\myfunnypipe" )

void process_callback( PROCESSENTRY32 *proc ) {
	if ( strcmp( proc->szExeFile, "notepad.exe" ) != 0 ) {
		return;
	}

	printf( "(+) found notepad %d\n", proc->th32ProcessID );

	char cwd[ MAX_PATH ];
	GetCurrentDirectory( sizeof( cwd ), cwd );

	char dll_path[ MAX_PATH ];
	snprintf( dll_path, sizeof( dll_path ), "%s\\" DLL_NAME, cwd );

	if ( win_inject( proc->th32ProcessID, dll_path ) ) {
		puts( "(+) injected" );
	} else {
		printf( "(-) couldn't inject (%d)\n", GetLastError( ) );
	}
}

int main( ) {
	system( "pause" );
	bool quit = false;
	ipc_init( PIPE_NAME, &quit );
	win_foreach_process( process_callback );
	while ( true ) {
		if ( quit ) {
			return EXIT_SUCCESS;
		}
		Sleep( 5000 );
	}
	return EXIT_SUCCESS;
}