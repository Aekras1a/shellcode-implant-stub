@echo off
if exist stub-dll.obj del stub-dll.obj
if exist stub-dll.dll del stub-dll.dll
\masm32\bin\ml /c /coff stub-dll.asm
\masm32\bin\Link /SUBSYSTEM:WINDOWS /DLL /DEF:stub-dll.def stub-dll.obj 
del stub-dll.obj
del stub-dll.exp
dir stub-dll.*
pause
