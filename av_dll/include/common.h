#ifndef COMMON_H
#define COMMON_H

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

// Windows
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <pe.h>
#include <windows_helper.h>

// Syscalls
#include <hwbp_direct_syscalls.h>
#include <instr_direct_syscalls.h>
#include <indirect_syscalls.h>

#include <rwx.h>

// Hook
#include <hook.h>
#include <module_hooks.h>

#include <vec.h>

#include <ipc.h>

#include <log.h>

#include <av.h>

#include <disasm.h>
#include <bddisasm.h>

#endif // COMMON_H
