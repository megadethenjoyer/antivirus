#ifndef AV_H
#define AV_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void av_init( HMODULE module );
void av_uninit( );

bool av_is_whitelisted( void *address );

#endif // AV_H