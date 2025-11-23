
#include <assert.h>
#include "smipc.h"

volatile struct buf *buf = NULL;

void smipc_init( ) {
	HANDLE file = CreateFileMapping( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1024, "Local\\MyAmazingFile" );
	assert( file != NULL );

	void *view = MapViewOfFile( file, FILE_MAP_ALL_ACCESS, 0, 0, 1024 );
	assert( view != NULL );

	buf = view;
}