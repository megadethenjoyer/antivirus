#ifndef LOCK_H
#define LOCK_H

#include <intrin.h>

#define LOCK( x )   do { } while ( _InterlockedCompareExchange( ( x ), 1, 0 ) )
#define UNLOCK( x ) _InterlockedExchange( ( x ), 0 );

#endif // LOCK_H