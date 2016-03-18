; -----------------------------------------------------------------------------
; 
;  Implant Stub Code - MASM EXE
;  (C) Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>
;
;  This code is designed to act as a basis for safer implants during simulated
;  attacks. 
;
;  Compile this by running 'makeit.bat' from the same drive as a masm32 installation.
; 
; -----------------------------------------------------------------------------

.586
.model flat,stdcall
option casemap:none

; -----------------------------------------------------------------------------
;  These includes are needed for the compiler and linker
; -----------------------------------------------------------------------------

include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib           

; -----------------------------------------------------------------------------
;  MASM works by single-pass, so all functions need to be declared
;  in advance so that the lexcial analyser will work properly
; -----------------------------------------------------------------------------

CheckExecution PROTO 
MutexCheck PROTO
GetComputerInfo PROTO :DWORD


.data         
                     
; The mutex name. "Local\" means per session. "Global\" means per system. Change it to whatever you want.
strMutexName  db  "Global\Stufus",0    

; Had to work this out from msdn.microsoft.com/en-us/library/windows/desktop/ms724224%28v=vs.85%29.aspx
; and some experimentation
CNF_ComputerNamePhysicalNetBIOS           equ 4
CNF_ComputerNamePhysicalDnsHostname       equ 5
CNF_ComputerNamePhysicalDnsDomain         equ 6
CNF_ComputerNamePhysicalDnsFullyQualified equ 7

; Replace this with the actual shellcode to run (e.g. from metasploit or cobalt strike etc)
shellcode db 90h,90h
  
.data?
            
.code 
stufus:

; -----------------------------------------------------------------------------
;  Entry point
; -----------------------------------------------------------------------------
 
invoke CheckExecution       ; This does the main work
invoke ExitProcess, NULL    ; Exit cleanly when the time comes



; -----------------------------------------------------------------------------
; 
;  CheckExecution
;  This function does all of the work; it will go through the relevant checks
;  and execute the shellcode if they all pass.
; 
; -----------------------------------------------------------------------------

CheckExecution PROC uses esi

    ; Get the physical NETBIOS name of the host
    invoke GetComputerInfo, CNF_ComputerNamePhysicalNetBIOS
    mov esi, eax
    invoke MessageBox, NULL, esi, NULL, NULL
    invoke GlobalFree, esi
    
    invoke MutexCheck ; Check to see whether the implant is already running or not
    .if eax==NULL
        nop
    .else
        nop
    .endif
    ret
    
CheckExecution ENDP



; -----------------------------------------------------------------------------
; 
;  GetComputerInfo
;  This function retrieves information about the computer (e.g. its name)
;  and returns a buffer to it. Caller needs to free it when done.
; 
; -----------------------------------------------------------------------------

GetComputerInfo PROC uses esi reqinfo:DWORD
LOCAL lsize:DWORD
    mov lsize, 0
    invoke GetComputerNameEx, reqinfo, NULL, addr lsize ; Find out how large this string actually is
    inc lsize
    invoke GlobalAlloc, GPTR, lsize                     ; Allocate the memory needed to store the name
    test eax, eax                                       ; Make sure the function worked
    jz done
    mov esi, eax
    invoke GetComputerNameEx, reqinfo, esi, addr lsize  ; Actually retrieve it
    test eax, eax
    jz done
    mov eax, esi 
done:
    ret
GetComputerInfo ENDP



; -----------------------------------------------------------------------------
; 
;  MutexCheck
;  This function attempts to create the mutex stored in 'strMutexName'. It will
;  return 0 in eax if the mutex already existed and return -1 if it did not.
;
;  0 = Don't go any further, its already running.
;  1 = Continue execution.
; 
; -----------------------------------------------------------------------------

MutexCheck PROC 
 invoke CreateMutex, NULL, TRUE, addr strMutexName
 .if eax==NULL
      xor eax, eax
      ret
 .else
      invoke GetLastError
      .if eax==ERROR_ALREADY_EXISTS
          xor eax, eax
          ret
      .else
          mov eax, -1
          ret
      .endif
 .endif
MutexCheck ENDP

End stufus