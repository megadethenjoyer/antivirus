extern g_RtlRestoreContext: qword
extern c_exception_dispatcher: proc

.code

KiUserExceptionDispatcher_hook proc

	cld

	mov rcx, rsp
	push rcx
	sub rsp, 18h
	call c_exception_dispatcher
	add rsp, 18h

	pop rcx ; Context Record
	test eax, eax
	jz continue

	lea rdx, [rcx + 4F0h] ; Exception Record
	sub rsp, 18h
	jmp g_RtlRestoreContext

continue:
	ret


KiUserExceptionDispatcher_hook endp

end