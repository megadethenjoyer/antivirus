#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdbool.h>
#include "ipc.h"

#define BUFSIZE ( 1024 )

bool *g_quit = { 0 };

DWORD WINAPI thread_proc( void *param ) {
	HANDLE pipe = param;

	char *request = HeapAlloc( GetProcessHeap( ), 0, BUFSIZE );

	while ( true ) {
		DWORD bytes_read = 0;
		bool success = ReadFile(
			pipe,
			request,
			BUFSIZE,
			&bytes_read,
			NULL );

		if ( !success || bytes_read == 0 ) {
			if ( GetLastError( ) == ERROR_BROKEN_PIPE ) {
				printf( "(-) client disconnected\n" );
			} else {
				printf( "(-) pipe read fail (%d)\n", GetLastError( ) );
			}
			break;
		}

		DWORD pid = { 0 };
		if ( !GetNamedPipeClientProcessId( pipe, &pid )  ) {
			printf( "(-) Failed to get client PID (%d)\n", GetLastError( ) );
		}
		printf( "(*) req from client (PID %d): %s\n", pid, request );
	}

	FlushFileBuffers( pipe );
	DisconnectNamedPipe( pipe );
	CloseHandle( pipe );

	HeapFree( GetProcessHeap( ), 0, request );
	return TRUE;
}

DWORD WINAPI init_thread( void *pipe_name ) {
	puts( "(#) init_thread" );
	while ( true ) {
		HANDLE pipe = CreateNamedPipe(
			pipe_name,
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL );                    // default security attribute 

		if ( pipe == INVALID_HANDLE_VALUE ) {
			printf( "(-) CreateNamedPipe failed (%d)\n", GetLastError( ) );
			return;
		}

		bool connected = ConnectNamedPipe( pipe, NULL ) ? true : ( GetLastError( ) == ERROR_PIPE_CONNECTED );

		if ( !connected ) {
			printf( "(-) Failed to connect pipe (%d)\n", GetLastError( ) );
			CloseHandle( pipe );
			continue;
		}

		printf( "(*) pipe connect\n" );

		HANDLE thread = CreateThread(
			NULL,
			0,
			thread_proc,
			( void * )pipe,
			0,
			NULL );

		CloseHandle( thread );

	}
}

void ipc_init( const char *pipe_name, bool *quit ) {
	g_quit = quit;
	CloseHandle( CreateThread( NULL, 0, init_thread, pipe_name, 0, NULL ) );
}