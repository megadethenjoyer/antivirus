#ifndef PE_H
#define PE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

size_t pe_get_image_size( uint8_t *image );
bool pe_verify_sig( const wchar_t *path );
uint8_t *pe_get_function_base( HMODULE module, uint8_t *instr );

#endif // PE_H