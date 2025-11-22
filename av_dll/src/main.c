#include <common.h>

#pragma comment( lib, "bddisasm.lib" )
#pragma comment( lib, "wintrust.lib" )

void nd_memset( void *buf, int v, size_t s ) {
	memset( buf, v, s );
}

DWORD WINAPI main_thread( void *param ) {
	av_init( ( HMODULE )( param ) );
}

DWORD WINAPI DllMain( HMODULE module, DWORD reason, void *reserved ) {
	if ( reason == DLL_PROCESS_ATTACH ) {
		DisableThreadLibraryCalls( module );
		HANDLE h = CreateThread( NULL, 0, main_thread, module, 0, NULL );
		assert( h );

		CloseHandle( h );
	}
	if ( reason == DLL_PROCESS_DETACH ) {
		av_uninit( module );
	}
	
	return TRUE;
}