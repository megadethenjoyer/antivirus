debug/
  includes stuff useful for debugging av_dll.dll

detection/
  includes stuff actually relevant for the AV (detection vectors)

hook/
  includes stuff useful for hooking

ipc/
  includes IPC stuff (av_dll.dll <-> main_module.exe)

windows/
  includes Windows specific stuff


main.c
  includes DllMain
  calls av_init( )

av.c
  includes av_init( )
           av_deinit( )