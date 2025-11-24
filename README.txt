User mode hook-based antivirus

The general idea is:
 - Don't* detect behavior (there are already other and better solutions for that)
 - Detect methods of achieving behavior
 - For example, detect direct and indirect syscalls
 
*Ideally this will also get extended to detect *some* behavior, i.e. block network activity
 for programs that shouldn't need it, etc. but that's currently not implemented

Currently implemented:
 - main_module/
   - simple test injector, right now just injects into notepad.exe
   - has IPC to av_dll.dll (injected in notepad.exe)
   - should also inject to newly spawned processes (hook NtCreateUserProcess with av_dll.dll)
 - av_dll/
   - src/detection/syscall/
     > instr_direct_syscalls.c  = Detects direct syscalls by scanning for 0x0F 05 instructions
       - Problem here that `mov rax, 0x050F` also contains 0x0F 05, and yet it isn't a syscall
       - It gets the function base and disassembles to check whether 0F 05 is part of another instruction
         or its own (syscall)
       - Unfortunately an attacker could do `mov rax, 0x050F` which wouldn't get detected and
         then just jmp to that 0F 05
       - This is why I also implemented HWBP based detection:
     -> hwbp_direct_syscalls.c  = Detects direct syscalls by setting hardware breakpoints
                                  and catching them with a VEH (or dispatcher hook, see av.c)
       - The problem is there is only 4 debug registers, so if there's for example 5 direct syscalls to hook,
         I protect the non-hooked ones with R-- (instead of R-X), and then when an R-- page is executed, the
         VEH hits and I can refresh the debug registers with the new pages. Of course the old contents have to
         be R-- protected aswell

Need to also implement: detection of new modules
                        don't allow RWX pages at all
                        don't allow mapping executable code, if it isn't a library (suspicious)

In the end this means that every single syscall possible is hooked. But then how does the program do stuff?
    - IPC (through shared memory) to main_module.exe which then suspends the entire process, writes the syscall to the thread, resumes only that thread,
      upon syscall execution finished, return to main_module.exe and overwrite the syscall back. Resume whole process

    - This way the program can do stuff, and yet every syscall can be checked (and prevented!*) from usermode.
( Currently this is implemented but has some bugs, race conditions, crashes, hangs, bad stuff. TODO: make a simpler test program,
  right now I'm testing with notepad.exe which has all sorts of edge cases and is a pain to debug )


*you could also do instrumentation callbacks of some sort but you can't easily check the parameters and worst of all, you can't prevent the call
 also, the attacker could just overwrite your callback and then it doesn't get called

The problem with this approach is that:
- you can add as small a sleep in main_module.exe and it's really really slow (~1ms/syscall)
- you can add no sleep and main_module.exe will take 99% CPU

But it's just a PoC of what you can do from usermode anyway, not meant to be used ;)

Any help/PRs/testing would be appreciated, I tried to make the code as clean as possible to make contributing (or at least studying from it) as easy as possible

If you have any questions, you can contact me mdenjoyer@proton.me, or ideally make a PR/issue