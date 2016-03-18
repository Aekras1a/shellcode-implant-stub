@echo off

    if exist "stub-exe.obj" del "stub-exe.obj"
    if exist "stub-exe.exe" del "stub-exe.exe"

    \masm32\bin\ml /c /coff "stub-exe.asm"
    if errorlevel 1 goto errasm

    \masm32\bin\PoLink /SUBSYSTEM:WINDOWS "stub-exe.obj"
    if errorlevel 1 goto errlink
    dir "stub-exe.*"
    goto TheEnd

  :errlink
    echo _
    echo Link error
    goto TheEnd

  :errasm
    echo _
    echo Assembly Error
    goto TheEnd
    
  :TheEnd

pause
