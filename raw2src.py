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
import argparse

domainhash = hashlib.sha1()
domainhash.update("TESTER2")
domainhash_value = domainhash.digest()
domainhash_size = domainhash.digest_size

# Read the shellcode from shellcode.raw
with open('shellcode.raw', 'rb') as s:
    shellcode = s.read()
    s.close()

def writeout(varname, data, xorval, fmt):
	hash_counter = 0
	shellcode_counter = 0
	sys.stdout.write(varname+" db ")
	for c in shellcode:
	    if shellcode_counter % 20:
	        sys.stdout.write(',')
	    elif shellcode_counter:
	        sys.stdout.write("\n" + " "*varname.length() + "db ")
	
        if xorval != None:
	        original_opcode = c
	        new_opcode = ord(c) ^ ord(domainhash_value[hash_counter])
        else:
            new_opcode = ord(c)
	    sys.stdout.write(str(new_opcode))
	
	    shellcode_counter += 1

        if xorval != None:
		    if hash_counter==domainhash_size - 1:
		        hash_counter = 0
		    else:
		        hash_counter = hash_counter + 1

    sys.stdout.write("\n")
    sys.stdout.write("shellcodelen  equ  "+str(shellcode_counter)+"\n")

def generate_computername_hash(computername, outformat):
    computernamehash = hashlib.sha1()
    computernamehash.update(computername)
    computernamehash_value = domainhash.digest()
    writeout("hashSHA1CompterName", computernamehash_value, None, outformat)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Shellcode to C/ASM implant stub converter.')
    parser.add_argument('-c', '--computername', action='store', help='Generate the SHA1 hash of the parameter given (e.g. a computer name)')
    parser.add_argument('-x', '--xor', action='store', help='XOR the shellcode with the hash of the parameter given (e.g. domain name)')
    parser.add_argument('-s', '--shellcode', action='store', help='The filename containing the shellcode. Specify "-" to read from STDIN')
    parser.add_argument('-o', '--output-format', action='store', help='The output format. Can be "C" or "MASM"')
    args = vars(parser.parse_args())

    if 'output-format' in args and args['output-format'] != None:
        if args['output-format'] != 'C' and args['output-format'] != 'MASM':
            sys.stderr.write("Invalid output format\n")
            sys.exit(1)
    
    if 'computername' in args and args['computername'] != None:
        
