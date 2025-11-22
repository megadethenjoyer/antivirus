#ifndef HOOK_H
#define HOOK_H
#include <stdbool.h>
#include <stdint.h>

bool hook_create( uint8_t *func, void *fn_detour, void *marker );
void hook_disable_all( );

#endif // HOOK_H