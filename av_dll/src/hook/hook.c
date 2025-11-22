#include <common.h>

struct hook {
	uint8_t *func;
	uint8_t *hop;
	size_t overwrite_size;
};
// struct hook
struct vec hooks = { 0 };


#define PRESERVE_BUFFER_SIZE ( 6 )
#define DETOUR_BUFFER_SIZE   ( 43 )
#define RESTORE_BUFFER_SIZE  ( 6 )
#define STATIC_BUFFER_SIZE   ( PRESERVE_BUFFER_SIZE + DETOUR_BUFFER_SIZE + RESTORE_BUFFER_SIZE )
#define CONTINUE_BUFFER_SIZE ( 14 )
#define ORIGINAL_OFFSET      ( PRESERVE_BUFFER_SIZE + DETOUR_BUFFER_SIZE + RESTORE_BUFFER_SIZE )

// Joins preserve_buffer, detour_buffer and restore_buffer into static_buffer.
void init_static_buffer( uint8_t *buffer, uint8_t *preserve_buffer, uint8_t *detour_buffer, uint8_t *restore_buffer ) {
	uint8_t *ptr = buffer;

	memcpy( ptr, preserve_buffer, PRESERVE_BUFFER_SIZE );
	ptr += PRESERVE_BUFFER_SIZE;
	
	memcpy( ptr, detour_buffer, DETOUR_BUFFER_SIZE );
	ptr += DETOUR_BUFFER_SIZE;
	
	memcpy( ptr, restore_buffer, RESTORE_BUFFER_SIZE );
}

void *create_hop( struct hook *h, void *detour, void *marker ) {
	/* push rcx          <--- preserve_buffer
	   push rdx
	   push r8
	   push r9
	   mov r8, rcx       <--- detour_buffer
	   mov rcx, (marker)
	   mov rdx, (func)
	   mov rax, (detour)
	   sub rsp, 0x18
	   call rax
	   add rsp, 0x18
	   pop r9            <--- restore_buffer
	   pop r8
	   pop rdx
	   pop rcx
	
	   ... original instructions ... <--- [func (overwrite_size)]
	   jmp qword [rip] <--- continue_instr
	   dq (next) */

	uint8_t preserve_buffer[ PRESERVE_BUFFER_SIZE ] = {
		0x51,		// push rcx
		0x52,		// push rdx
		0x41, 0x50, // push r8
		0x41, 0x51  // push r9
	};

	uint8_t detour_buffer[ DETOUR_BUFFER_SIZE ] = {
		0x49, 0x89, 0xC8, // mov r8, rcx
		0x48, 0xB9, /* (marker)    -> */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx
		0x48, 0xBA, /* (func)      -> */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx
		0x48, 0xB8, /* (detour)    -> */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax
		0x48, 0x83, 0xEC, 0x18, // sub rsp, 0x18
		0xFF, 0xD0,  // call rax
		0x48, 0x83, 0xC4, 0x18 // add rsp, 0x18
	};

	uint8_t restore_buffer[ RESTORE_BUFFER_SIZE ] = {
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5A,       // pop rdx
		0x59        // pop rcx
	};


	*( uint64_t * )( detour_buffer + 5 )  = ( uint64_t )( marker );
	*( uint64_t * )( detour_buffer + 15 ) = ( uint64_t )( h->func );
	*( uint64_t * )( detour_buffer + 25 ) = ( uint64_t )( detour );

	uint8_t continue_buffer[ CONTINUE_BUFFER_SIZE ] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword [rip + 0]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	*( uint64_t * )( continue_buffer + 6 ) = ( uint64_t )( h->func + h->overwrite_size );

	size_t buffer_size = sizeof( preserve_buffer ) + sizeof( detour_buffer ) + sizeof( restore_buffer ) + h->overwrite_size + 12;
	uint8_t *buffer = ( uint8_t * )VirtualAlloc( NULL, buffer_size,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( buffer == NULL ) {
		return false;
	}

	h->hop = buffer;

	uint8_t static_buffer[ STATIC_BUFFER_SIZE ] = { 0 };
	init_static_buffer( static_buffer, preserve_buffer, detour_buffer, restore_buffer );
	
	// Copy static_buffer to hop.
	memcpy( buffer, static_buffer, STATIC_BUFFER_SIZE );

	// Copy original instructions from func to the hop.
	memcpy( buffer + STATIC_BUFFER_SIZE, h->func, h->overwrite_size );

	// Copy continue_buffer.
	memcpy( buffer + STATIC_BUFFER_SIZE + h->overwrite_size, continue_buffer, sizeof( continue_buffer ) );

	DWORD old_protect = { 0 };
	VirtualProtect( buffer, buffer_size, PAGE_EXECUTE_READ, &old_protect );

	return buffer;
}

bool hook_create( uint8_t *func, void *fn_detour, void *marker ) {
	if ( *func == 0xE9 ) {
		// JMP stub
		int32_t rva = *( uint32_t * )( func + 1 );
		return hook_create( func + 5 + rva, fn_detour, marker );
	}

	struct hook hook = { 0 };
	hook.func = func;

	hook.overwrite_size = disasm_find_good_size( 12, func );
	if ( hook.overwrite_size == 0 ) {
		return false;
	}

	void *hop = create_hop( &hook, fn_detour, marker );
	if ( hop == NULL ) {
		return false;
	}

	vec_push( &hooks, hook );

	DWORD old_protect = { 0 };
	VirtualProtect( func, hook.overwrite_size, PAGE_EXECUTE_READWRITE, &old_protect );

	uint8_t detour_buffer[ 12 ] = {
		0x48, 0xB8, /* ( hop ) -> */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xE0 // jmp rax
	};

	*( uint64_t * )( detour_buffer + 2 ) = ( uint64_t )( hop );

	memcpy( func, detour_buffer, sizeof( detour_buffer ) );

	for ( int i = sizeof( detour_buffer ); i < hook.overwrite_size; i++ ) {
		*( func + i ) = 0x90; // NOP
	}

	VirtualProtect( func, hook.overwrite_size, old_protect, &old_protect );
	return true;
}

void unhook_one( struct hook *hook ) {
	// R-X -> RWX
	DWORD old_protect = { 0 };
	VirtualProtect( hook->func, hook->overwrite_size, PAGE_EXECUTE_READWRITE, &old_protect );

	// copy original instructions from trampoline/hop
	memcpy( hook->func, hook->hop + ORIGINAL_OFFSET, hook->overwrite_size );

	// RWX -> R-X
	VirtualProtect( hook->func, hook->overwrite_size, old_protect, &old_protect );

	// free( trampoline )
	VirtualFree( hook->hop, 0, MEM_RELEASE );
}

void hook_disable_all( ) {
	for ( uint32_t index = 0; index < vec_len( &hooks, struct hook ); index++ ) {
		struct hook hook = { 0 };
		vec_get( &hooks, struct hook, index, &hook );
		
		unhook_one( &hook );
	}

	vec_free( &hooks );
}