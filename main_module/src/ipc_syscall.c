#include "smipc.h"
#include <winternl.h>
#include <stdint.h>
#include <assert.h>
#include <tlhelp32.h>
#include "ipc_syscall.h"

#define STATUS_SUCCESS ( ( NTSTATUS )( 0x00000000 ) )
#define STATUS_BUFFER_TOO_SMALL ( ( NTSTATUS )( 0xC0000023 ) )

typedef uint32_t( *NtDelayExecution_t )( BOOLEAN alertable, int64_t * );
typedef uint32_t( *NtWriteVM_t )( HANDLE h_process, void *base, void *buf, size_t size, size_t *written );
typedef uint32_t( *NtOpenThread_t )( HANDLE *ph_thread, ACCESS_MASK, OBJECT_ATTRIBUTES *, CLIENT_ID * );
typedef uint32_t( *NtSuspendThread_t )( HANDLE h_thread, void * );
typedef uint32_t( *NtSuspendProcess_t )( HANDLE h_proc );
typedef uint32_t( *NtResumeProcess_t )( HANDLE h_proc );
typedef uint32_t( *NtResumeThread_t )( HANDLE h_thread, uint32_t * );
typedef uint32_t( *NtGetContextThread_t )( HANDLE h_thread, CONTEXT *ctx );
typedef uint32_t( *NtSetContextThread_t )( HANDLE h_thread, CONTEXT *ctx );
typedef uint32_t( *NtQuerySystemInfo_t )( SYSTEM_INFORMATION_CLASS info_class, void *out, uint32_t size, uint32_t *out_size );
typedef uint32_t( *NtSetTimerResolution_t )( uint32_t resolution, BOOLEAN set, uint32_t *current );
typedef uint32_t( *NtProtectVM_t )( HANDLE h_process, void **p_base, size_t *p_size, uint32_t protect, uint32_t *p_old_protect );

NtResumeThread_t g_NtResumeThread = 0;

void suspend_all_threads( HANDLE process ) {
	HANDLE h = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	THREADENTRY32 t = { 0 };
	t.dwSize = sizeof( t );
	Thread32First( h, &t );

	while ( 1 ) {
		if ( !Thread32Next( h, &t ) ) {
			break;
		}

		if ( t.th32OwnerProcessID != GetProcessId( process ) ) {
			continue;
		}

		
		HANDLE th = OpenThread( THREAD_ALL_ACCESS, 0, t.th32ThreadID );
		SuspendThread( th );
		CloseHandle( th );
	}

	CloseHandle( h );

}
void resume( HANDLE process ) {
	HANDLE h = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	THREADENTRY32 t = { 0 };
	t.dwSize = sizeof( t );
	Thread32First( h, &t );

	while ( 1 ) {
		if ( !Thread32Next( h, &t ) ) {
			break;
		}

		if ( t.th32OwnerProcessID != GetProcessId( process ) ) {
			continue;
		}

		
		HANDLE th = OpenThread( THREAD_ALL_ACCESS, 0, t.th32ThreadID );
		ResumeThread( th );
		CloseHandle( th );
	}

	CloseHandle( h );
}


void resume_thread( HANDLE h_thread ) {
	while ( 1 ) {
		int32_t n = 0;
		if ( g_NtResumeThread( h_thread, &n ) != STATUS_SUCCESS ) {
			break;
		}
		if ( n <= 1 ) {
			break;
		}
	}	
}


void is_work( ) {
	HMODULE ntdll = GetModuleHandle( "ntdll" );
	assert( ntdll != NULL );

	NtDelayExecution_t NtDelayExecution = GetProcAddress( ntdll, "NtDelayExecution" );
	assert( NtDelayExecution != NULL );

	NtWriteVM_t NtWriteVM = GetProcAddress( ntdll, "NtWriteVirtualMemory" );
	assert( NtWriteVM != NULL );

	NtOpenThread_t NtOpenThread = GetProcAddress( ntdll, "NtOpenThread" );
	assert( NtOpenThread != NULL );

	NtSuspendThread_t NtSuspendThread = GetProcAddress( ntdll, "NtSuspendThread" );
	assert( NtSuspendThread != NULL );

	NtSuspendProcess_t NtSuspendProcess = GetProcAddress( ntdll, "NtSuspendProcess" );
	assert( NtSuspendProcess != NULL );

	NtResumeThread_t NtResumeThread = GetProcAddress( ntdll, "NtResumeThread" );
	assert( NtResumeThread != NULL );

	g_NtResumeThread = NtResumeThread;

	NtResumeProcess_t NtResumeProcess = GetProcAddress( ntdll, "NtResumeProcess" );
	assert( NtResumeProcess != NULL );

	NtGetContextThread_t NtGetContextThread = GetProcAddress( ntdll, "NtGetContextThread" );
	assert( NtGetContextThread != NULL );

	NtSetContextThread_t NtSetContextThread = GetProcAddress( ntdll, "NtSetContextThread" );
	assert( NtSetContextThread != NULL );

	NtProtectVM_t NtProtectVM = GetProcAddress( ntdll, "NtProtectVirtualMemory" );
	assert( NtProtectVM != NULL );

	NtSetTimerResolution_t NtSetTimerResolution = GetProcAddress( ntdll, "NtSetTimerResolution" );
	if ( NtSetTimerResolution ) {
		uint32_t current = { 0 };
		NtSetTimerResolution( 1, TRUE, &current );
	}
	int64_t delay = -1; // 100ns

	HANDLE h_process = NULL;
	HANDLE h_thread = NULL;
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL; // CONTEXT_CONTROL | CONTEXT_INTEGER;
	void *sb = NULL;
	void *rip = NULL;
	void *exec_stub = NULL;

	OBJECT_ATTRIBUTES obj = { 0 };
	obj.Length = sizeof( obj );

	CLIENT_ID cid = { 0 };
	BOOL expecting_post = FALSE;

	while ( 1 ) {


		if ( buf->type == msg_syscall ) {
			buf->type = msg_ip;
			//NtSuspendProcess( h_process );
			suspend_all_threads( h_process );

			uint8_t execute_buf[ ] = {
				0x0F, 0x05, // syscall

				0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, // mov r10, ... (buf)
				0x41, 0xC7, 0x02, 0x04, 0x00, 0x00, 0x00, // mov [r10], 4 (msg_post)

				// .x:
				0x41, 0x83, 0x3A, 0x03, // cmp dword [r10], 3 (msg_done)
				0x75, 0xFA,  // jne .x

				0x41, 0xFF, 0x62, 0x04, // jmp qword [r10 + 4]
			};

			*( uint64_t * )( execute_buf + 4 ) = sb;

			void *base = exec_stub;
			size_t size = sizeof( execute_buf );

			DWORD old_protect = { 0 };
			NtProtectVM( h_process, &base, &size, PAGE_READWRITE, &old_protect );
			NtWriteVM( h_process, exec_stub, execute_buf, sizeof( execute_buf ), NULL );
			NtProtectVM( h_process, &base, &size, PAGE_EXECUTE_READ, &old_protect );

			cid.UniqueThread = ( HANDLE )( ( uint64_t )( buf->syscall.tid ) );
			NtOpenThread( &h_thread, THREAD_ALL_ACCESS, &obj, &cid );
			assert( h_thread );
			//NtSuspendThread( h_thread, NULL );

			NtGetContextThread( h_thread, &ctx );
			//printf( "syscall %x with params %llx %llx %llx %llx\n", ( uint32_t )( ctx.Rax ), ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9 );

			rip = ctx.Rip;

			ctx.R10 = ctx.Rcx;
			ctx.Rip = exec_stub;

			NtSetContextThread( h_thread, &ctx );

			expecting_post = TRUE;

			NtResumeThread( h_thread, NULL );
		}

		if ( buf->type == msg_init ) {
			puts( "got init" );
			buf->type = msg_ip;
			exec_stub = buf->init.exec_stub;
			h_process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, buf->init.pid );
			sb = buf->init.sb;
			buf->type = msg_done;
			puts( "init done" );
		}

		if ( buf->type == msg_post ) {
			expecting_post = FALSE;

			DWORD old_protect = { 0 };

			void *base = exec_stub;
			char zeroes[ 2 ] = { 0 };
			size_t size = sizeof( zeroes );



			NtProtectVM( h_process, &base, &size, PAGE_EXECUTE_READWRITE, &old_protect ); // still being executed so have to RWX
			NtWriteVM( h_process, exec_stub, zeroes, sizeof( zeroes ), NULL );
			NtProtectVM( h_process, &base, &size, PAGE_EXECUTE_READ, &old_protect );

			NtGetContextThread( h_thread, &ctx );
			//printf( "ret %x\n", ( uint32_t )( ctx.Rax ) );

			//printf( "jump backt to %p, exec_stub=%p\n", rip, exec_stub );
			buf->post.jmp = rip;
			//NtResumeProcess( h_process );
			resume( h_process );
			buf->type = msg_done;
		}

		if ( !expecting_post ) {
			//NtDelayExecution( FALSE, &delay );
		}
	}


}

