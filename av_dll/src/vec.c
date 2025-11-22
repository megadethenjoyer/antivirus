#include <common.h>

void vec_internal_push( struct vec *v, size_t el_size, void *el_buf ) {
	LOCK( &v->lock );
	size_t old_size = v->size;
	v->size += el_size;
	v->buf = realloc( v->buf, v->size );
	assert( v->buf );

	void *added = ( uint8_t * )( v->buf ) + old_size;
	memcpy( added, el_buf, el_size );
	UNLOCK( &v->lock );
}

void vec_internal_pop_first( struct vec *v, size_t size, void *to_buf ) {
	LOCK( &v->lock );
	memcpy( to_buf, v->buf, size );
	v->size -= size;
	void *new_buf = malloc( v->size );
	assert( new_buf );
	memcpy( new_buf, ( uint8_t * )( v->buf ) + size, v->size );
	free( v->buf );
	v->buf = new_buf;
	UNLOCK( &v->lock );
}
void vec_internal_pop_last( struct vec *v, size_t size, void *to_buf ) {
	LOCK( &v->lock );
	v->size -= size;
	memcpy( to_buf, ( uint8_t * )( v->buf ) + v->size, size );
	v->buf = realloc( v->buf, v->size );
	assert( v->buf );
	UNLOCK( &v->lock );
}

void vec_internal_at( struct vec *v, uint64_t i, size_t size, void *out ) {
	LOCK( &v->lock );
	memcpy( out, ( uint8_t * )( v->buf ) + ( i * size ), size );
	UNLOCK( &v->lock );
}
