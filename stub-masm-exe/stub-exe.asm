; -----------------------------------------------------------------------------
; 
;  Implant Stub Code
;  (C) Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>
;
;  This code is designed to act as a basis for safer implants during simulated
;  attacks. 
; 
; -----------------------------------------------------------------------------

.486
.model flat,stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\user32.inc

include \masm32\include\kernel32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib           

MutexCheck PROTO 
RunIfNotAlreadyRunning PROTO

.data                              

  strMutexName  db  "Global\Stufus",0    ; The mutex name. "Local\" means per session. "Global\" means per system.
  strYesRun db "Yes, run",0
  strNo db "No, already running",0

  shellcode db 90h,90h
  
.data?            

.code 

stufus:

; -----------------------------------------------------------------------------
; Entry point
; -----------------------------------------------------------------------------
 
invoke CheckExecution
invoke ExitProcess, NULL



; -----------------------------------------------------------------------------
; 
;  CheckExecution
;  This function does all of the work; it will go through the relevant checks
;  and execute the shellcode if they all pass.
; 
; -----------------------------------------------------------------------------

CheckExecution PROC

    ; Check to see whether the implant is already running or not
    invoke MutexCheck
    .if eax==NULL
        invoke MessageBox, NULL, addr strNo, NULL, NULL
    .else
        invoke MessageBox, NULL, addr strYesRun, NULL, NULL
    .endif
    ret
CheckExecution ENDP



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