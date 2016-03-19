#!/usr/bin/env python
#
#  Raw shellcode to source converter
#  (C) 2016 Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>
#  MWR InfoSecurity, MWR Labs
# 
#  This tool is designed to be used in conjunction with the 'shellcode-implant-stub'
#  project. It can:
#  - Take raw shellcode and convert it to a format suitable for inclusion in a C/ASM projects
#  - XOR the shellcode with the hash of a known string (e.g. DNS domain name, host name etc)
#  - Provide the hash of a known string in a format for inclusion in the C/ASM projects
#
import sys
import hashlib

domainhash = hashlib.sha1()
domainhash.update("TESTER2")
domainhash_value = domainhash.digest()
domainhash_size = domainhash.digest_size

# Read the shellcode from shellcode.raw
with open('shellcode.raw', 'rb') as s:
    shellcode = s.read()
    s.close()

hash_counter = 0
shellcode_counter = 0
sys.stdout.write("shellcode db ")
for c in shellcode:
    if shellcode_counter % 20:
        sys.stdout.write(',')
    elif shellcode_counter:
        sys.stdout.write("\n" + " "*10 + "db ")

    original_opcode = c
    new_opcode = ord(c) ^ ord(domainhash_value[hash_counter])

    sys.stdout.write(str(new_opcode))

    shellcode_counter += 1
    if hash_counter==domainhash_size - 1:
        hash_counter = 0
    else:
        hash_counter = hash_counter + 1

sys.stdout.write("\n")
sys.stdout.write("shellcodelen  equ  "+str(shellcode_counter)+"\n")
