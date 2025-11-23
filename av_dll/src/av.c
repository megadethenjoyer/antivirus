#include <common.h>
#include <smipc.h>

HANDLE av_module = NULL;

void KiUserExceptionDispatcher_hook( );
void *g_RtlRestoreContext = NULL;

void av_init( HMODULE module ) {
	av_module = module;

	log_init( );

	log_info( "AV dll loaded" );

	HMODULE ntdll = GetModuleHandle( "ntdll" );
	assert( ntdll != NULL );

	void *KiUserExceptionDispatcher = GetProcAddress( ntdll, "KiUserExceptionDispatcher" );
	g_RtlRestoreContext = GetProcAddress( ntdll, "RtlRestoreContext" );


	//inds_init( );
	//inds_scan_all_regions( );

	//hwbpds_init( );
	//hwbpds_scan_all_regions( );
	
	ipc_init( );
	ipc_open_pipe( );

	log_info(	"KiUserExceptionDispatcher      = %p\n"
				"KiUserExceptionDispatcher_hook = %p\n"
				"g_RtlRestoreContext			= %p\n",	KiUserExceptionDispatcher,
															KiUserExceptionDispatcher_hook,
															g_RtlRestoreContext);

	// TODO: Make the KiUserExceptionDispatcher hook work
	// Why: relying on VEHs is bad because an attacker could
	//      simply overwrite them from the PEB (no syscalls)
	//
	// The issue: It's pretty much done, but hook_detour's
	//            trampoline crashes due to KiUser..
	//            having no prologue
	// Fix: Rewrite KiUser.., it ain't that long

	// This hooks KiUser.. which is the first thing called on exception,
	// hooked to exception.asm!KiUser.._hook, calls av.c!c_exception_dispatcher,
	// manually calls exception handlers from HWBPDS and INDS

	// hook_create( KiUserExceptionDispatcher, KiUserExceptionDispatcher_hook, NULL );

	smipc_init( );

	log_info( "is_init( )" );
	is_init( ntdll );
}

struct dispatcher_arg {
	CONTEXT ctx;
	EXCEPTION_RECORD exception;
};

BOOLEAN c_exception_dispatcher( struct dispatcher_arg *arg ) {
	
	EXCEPTION_POINTERS ep = {
		.ExceptionRecord = &arg->exception,
		.ContextRecord = &arg->ctx,
	};
	if ( hwbpds_veh( &ep ) == EXCEPTION_CONTINUE_EXECUTION ) {
		return TRUE;
	}

	// shouldn't happen
	if ( inds_veh( &ep ) == EXCEPTION_CONTINUE_EXECUTION ) {
		return TRUE;
	}
	
	// jz .continue
	return FALSE;
}

void av_uninit( ) {
	log_info( "AV dll unloading" );
	ipc_close( );

	hwbpds_deinit( );
	inds_deinit( );

	rwx_destroy( );
	
	log_deinit( );
}

bool av_is_whitelisted( void *address ) {
	HMODULE module_base = win_get_module_base( ( uintptr_t )( address ) );

	wchar_t asdf[ MAX_PATH ];
	if ( GetModuleFileNameW( module_base, asdf, sizeof( asdf ) /2 ) ) {
		if ( pe_verify_sig( asdf ) ) {
			return true;
		}
	}


	return module_base == av_module;
}
