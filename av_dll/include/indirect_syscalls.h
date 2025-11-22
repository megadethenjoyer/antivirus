#ifndef INDIRECT_SYSCALLS_H
#define INDIRECT_SYSCALLS_H

#include <windows_helper.h>
#include <stdbool.h>
#include <stdint.h>

void is_init( HMODULE ntdll );
bool is_check( uint8_t *func );

#endif // INDIRECT_SYSCALLS_H
