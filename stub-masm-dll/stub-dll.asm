.486                                      ; create 32 bit code
.model flat, stdcall                      ; 32 bit memory model
option casemap :none                      ; case sensitive 

include \masm32\include\windows.inc       ; main windows include file
include \masm32\include\masm32.inc        ; masm32 library include

include \masm32\include\gdi32.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc

includelib \masm32\lib\gdi32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib

.data?
  hInstance dd ?

.code

LibMain proc instance:DWORD,reason:DWORD,unused:DWORD 

    .if reason == DLL_PROCESS_ATTACH
      mov eax, instance
      mov hInstance, eax
      mov eax, TRUE                 

    .elseif reason == DLL_PROCESS_DETACH

    .elseif reason == DLL_THREAD_ATTACH

    .elseif reason == DLL_THREAD_DETACH

    .endif

    ret

LibMain endp

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

  comment * -----------------------------------------------------
          You should add the procedures your DLL requires AFTER
          the LibMain procedure. For each procedure that you
          wish to EXPORT you must place its name in the "stub-dll.def"
          file so that the linker will know which procedures to
          put in the EXPORT table in the DLL. Use the following
          syntax AFTER the LIBRARY name on the 1st line.
          LIBRARY stub-dll
          EXPORTS YourProcName
          EXPORTS AnotherProcName
          ------------------------------------------------------- *

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

end LibMain
