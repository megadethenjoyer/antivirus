#ifndef MODULE_HOOKS
#define MODULE_HOOKS

#include <stdbool.h>
#include <stdint.h>

void module_hook( uint8_t *module, bool check_syscalls, void( *fn_hook )( char *function_name, void *fn, void *param_1 ) );

#endif // MODULE_HOOKS