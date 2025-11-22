#ifndef INSTR_DIRECT_SYSCALLS_H
#define INSTR_DIRECT_SYSCALLS_H

/*
 *  HOW THIS WORKS
 * 
 * inds_scan_all_regions( ) finds syscall and int 0x3E instructions.
 * The problem here is, the syscall instruction (0F 05) could actually be part
 * of a legitimate instruction (`mov ax, 0x050F`). To prevent setting this to
 * `mov ax, 0xCCCC`, `.rdata` is checked to find the start of the function,
 * and a disassembler is used to verify the start of this instruction does actually
 * land on the 0F 05.
 *
 * If it doesn't, DON'T replace it with `CC CC`, and let `hwbp_direct_syscalls.h` handle this.
 * If it does, set it to `CC CC`, and let `inds_veh` handle this.
 *
 */

#include <stdint.h>

void inds_init( );
DWORD WINAPI inds_veh( EXCEPTION_POINTERS *info );
void inds_scan_all_regions( );
void inds_scan_region( uint8_t *ptr, size_t size );
void inds_deinit( );

#endif // INSTR_DIRECT_SYSCALLS_H
