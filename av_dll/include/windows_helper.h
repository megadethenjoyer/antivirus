#ifndef WINDOWS_HELPER_H
#define WINDOWS_HELPER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdbool.h>
#include <stdint.h>

bool win_is_in_module( uint8_t *address, uint8_t *module );
HMODULE win_get_module_base( uintptr_t address );

size_t win_get_page_size( );
#define win_get_page_mask( ) ( win_get_page_size(  ) - 1 )
#define win_mask_page( addr ) ( ( uintptr_t )( addr ) & ~( win_get_page_mask( ) ) )


#define win_is_protect_executable( protect ) ( protect == PAGE_EXECUTE || \
											   protect == PAGE_EXECUTE_READ || \
											   protect == PAGE_EXECUTE_READWRITE || \
											   protect == PAGE_EXECUTE_WRITECOPY )

bool win_is_syscall( uint8_t *ptr );

#endif // WINDOWS_HELPER_H
