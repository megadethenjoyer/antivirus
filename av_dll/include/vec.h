#ifndef VEC_H
#define VEC_H

#include <stdint.h>
#include <stddef.h>
#include "lock.h"

struct vec {
	size_t size;
	void *buf;

	volatile long lock;
};

void vec_internal_push( struct vec *v, size_t el_size, void *el_buf );
void vec_internal_pop_first( struct vec *v, size_t size, void *to_buf );
void vec_internal_pop_last( struct vec *v, size_t size, void *to_buf );
void vec_internal_at( struct vec *v, size_t off, size_t size, void *out );

#define vec_push( v, el ) ( vec_internal_push( ( v ), sizeof( ( el ) ), ( void * )( &( el ) ) ) )
#define vec_pop_first( v, type, buf ) ( vec_internal_pop_first( ( v ), sizeof( type ), ( void * )( buf ) ) )
#define vec_pop_last( v, type, buf ) ( vec_internal_pop_last( ( v ), sizeof( type ), ( void * )( buf ) ) )
#define vec_len( v, type ) ( ( uint32_t )( ( v )->size / sizeof( type ) ) )
#define vec_get( v, type, i, out ) ( vec_internal_at( ( v ), ( i ), sizeof( type ), ( out ) ) )
#define vec_free( v ) do { LOCK( &( ( v )->lock ) ); free( ( v )->buf ); ( v )->size = 0; ( v )->buf = (void*)0; UNLOCK( &( ( v )->lock ) ); } while ( 0 )

#endif // VEC_H