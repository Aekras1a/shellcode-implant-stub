Almost all simulated attacks will require, at some point, the installation of a RAT and the establishment of a command and control (C2) channel. Unless you use your own custom RAT, you have limited control over the code that you use; for example publicly available options include:

* Empire - https://github.com/PowerShellEmpire/Empire
* Meterpreter - https://www.metasploit.com/
* Cobalt Strike - https://www.cobaltstrike.com/
* Pupy - https://github.com/n1nj4sec/pupy
* Throwback - https://github.com/silentbreaksec/Throwback

There are three features that I have been looking for:

* A check to only allow the implant to run once (either per user or globally).
* Validation that the implant is being executed on the correct host or a host within scope.
* A check to ensure that the implant is not executed after a certain time (i.e. the end of the engagement).

This project centres around being able to place existing shellcode inside a container that performs the above checks before executing it. It is designed for implant safety, not for anti-virus or incident response evasion.

A full blog post is available at https://labs.mwrinfosecurity.com/blog/safer-shellcode-implants/
