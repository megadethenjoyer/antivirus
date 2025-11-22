#include <common.h>

#define PIPE_NAME ( "\\\\.\\pipe\\myfunnypipe" )

HANDLE pipe_file = { 0 };
typedef NTSTATUS( NTAPI *NtWriteFile_t )( HANDLE file, HANDLE event,
	void *apc_routine, void *apc_ctx, IO_STATUS_BLOCK *iosb, const void *buffer, size_t size, uint64_t *offset, uint32_t *key );

NtWriteFile_t NtWriteFile;

volatile LONG ipc_enabled_lock = 0;
bool g_ipc_enable = true;

void ipc_init( ) {
	HMODULE ntdll = GetModuleHandle( "ntdll" );
	assert( ntdll );

	NtWriteFile = ( NtWriteFile_t )GetProcAddress( ntdll, "NtWriteFile" );
	assert( NtWriteFile );
}

void ipc_open_pipe( ) {
	while ( true ) {
		pipe_file = CreateFile(
			PIPE_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		);

		// good pipe
		if ( pipe_file != INVALID_HANDLE_VALUE ) {
			break;
		}

		if ( GetLastError( ) != ERROR_PIPE_BUSY ) {
			ExitProcess( EXIT_FAILURE );
		}

		if ( !WaitNamedPipe( PIPE_NAME, NMPWAIT_WAIT_FOREVER ) ) {
			ExitProcess( EXIT_FAILURE );
		}

	}

	log_info( "Got pipe, set state.." );

	DWORD mode = PIPE_READMODE_MESSAGE;
	bool success = SetNamedPipeHandleState(
		pipe_file,
		&mode,
		NULL,
		NULL );
	if ( !success ) {
		log_error( "Failed to open pipe (%d)", GetLastError( ) );
		ExitProcess( EXIT_FAILURE );
	}

}

void ipc_close( ) {
	CloseHandle( pipe_file );
}

void ipc_set_enabled( bool enabled ) {
	LOCK( &ipc_enabled_lock );
	g_ipc_enable = enabled;
	UNLOCK( &ipc_enabled_lock );
}

void ipc_write( const char *buffer, size_t size ) {
	LOCK( &ipc_enabled_lock );
	if ( !g_ipc_enable ) {
		UNLOCK( &ipc_enabled_lock );
		return;
	}
	UNLOCK( &ipc_enabled_lock );
	IO_STATUS_BLOCK iosb = { 0 };
	NTSTATUS status = NtWriteFile( pipe_file, NULL, NULL, NULL, &iosb, buffer, size, NULL, NULL );
	if ( !NT_SUCCESS( status ) ) {
		g_ipc_enable = false;
		
		log_error( "Fail write pipe (0x%x)", ( uint32_t )status );
		MessageBox( NULL, "Fail pipe write.", "av_ipc", MB_ICONERROR | MB_OK );
	}
}

HANDLE ipc_get_handle( ) {
	return pipe_file;
}