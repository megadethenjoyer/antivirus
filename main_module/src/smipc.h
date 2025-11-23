#ifndef SMIPC_H
#define SMIPC_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>

#pragma pack( push, 1 )
enum message {
	msg_done = 3,
	msg_syscall = 2,
	msg_post = 4,
	msg_ip = 5,
	msg_init = 6,
};

struct buf {
	enum message type;
	union {
		struct {
			void *exec_stub;
			void *sb;
			uint32_t pid;
		} init;
		struct {
			uint32_t tid;
		} syscall;
		struct {
			void *jmp;
		} post;
	};
};
#pragma pack( pop )

volatile struct buf *buf;

void smipc_init( );

#endif // SMIPC_H
