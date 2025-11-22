#ifndef WINDOWS_HELPER_H
#define WINDOWS_HELPER_H

#include <tlhelp32.h>
#include <stdint.h>
#include <stdbool.h>

void win_foreach_process( void( *fn_callback )( PROCESSENTRY32 *proc ) );
bool win_inject( uint32_t pid, const char *dll_path );

#endif // WINDOWS_HELPER_H