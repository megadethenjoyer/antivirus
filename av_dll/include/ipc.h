#ifndef IPC_H
#define IPC_H

#include <windows_helper.h>

#include <stdbool.h>

void ipc_init( );
void ipc_open_pipe( );
void ipc_close( );
void ipc_write( const char *buffer, size_t size );
void ipc_set_enabled( bool enabled );
HANDLE ipc_get_handle( );

#endif // IPC_H