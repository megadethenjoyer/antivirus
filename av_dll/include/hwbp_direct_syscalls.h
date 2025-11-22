#ifndef HWBP_DIRECT_SYSCALLS_H
#define HWBP_DIRECT_SYSCALLS_H

/*
 *  HOW THIS WORKS
 * 
 * hwbpds_scan_region( ) finds syscall and int 0x3E instructions.
 * The page they're in gets R-- protected (from R-X).
 * When the VEH (hwbpds_veh) hits when trying to execute the page, protect
 * it back to R-X and set debug registers to the actual syscall instruction.
 * The VEH then hits because of the debug register.
 *    ---  DIRECT SYSCALL CAUGHT ---
 *
 * Edge cases:
 *  - dr0, dr1, dr2 and dr3 are already used (see note below)
 *     -> R-- protect the page they're used by again
 *
 *
 *  - There are more than 4 syscall instructions in a page (dr0, dr1, dr2 and dr3 all used by the same page)
 *     -> In theory:   single step everything
 *	   -> In practice: We can't do this (too slow),
 *	                   pray this doesn't happen.
 *                     If it does, show a MessageBox informing the user
 *
 * Note:
 *  - In the current state, I don't allow drN and drM to contain different pages
 *    as this is harder to implement (what this means is that only one page of
 *    protected_pages will ever be R-X). Feel free to make a PR, although I feel
 *    that this would compromise code readability too much to justify the speed gain.
 *
 */

#include <windows_helper.h>

#include <stdint.h>
#include <stddef.h>

void hwbpds_init( );

LONG NTAPI hwbpds_veh( EXCEPTION_POINTERS *info );

void hwbpds_scan_all_regions( );
void hwbpds_scan_region( uint8_t *ptr, size_t size );
void hwbpds_deinit( );

#endif // HWBPDIRECT_SYSCALLS_H