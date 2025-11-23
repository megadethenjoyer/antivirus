#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <smipc.h>
#include <assert.h>

void smipc_init( ) {
	HANDLE file = OpenFileMapping( FILE_MAP_ALL_ACCESS, FALSE, "Local\\MyAmazingFile" );
	assert( file != NULL );

	volatile void *view = MapViewOfFile( file, FILE_MAP_ALL_ACCESS, 0, 0, 1024 );
	assert( view != NULL );

	buf = view;
}