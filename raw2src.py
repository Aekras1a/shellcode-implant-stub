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

def writeout(varname, data, xorval, xorsize, fmt):
    hash_counter = 0
    shellcode_counter = 0

    if fmt=='MASM':
        sys.stdout.write(varname+" db ")
    elif fmt=='C':
        sys.stdout.write("BYTE "+varname+"[] =\n  \"\\x")

    for c in data:
        if shellcode_counter % 20:
            if fmt=='MASM':
                sys.stdout.write(',')
            elif fmt=='C':
                sys.stdout.write('\\x')
        elif shellcode_counter:
            if fmt=='MASM':
                sys.stdout.write("\n" + " "*len(varname) + " db ")
            elif fmt=='C':
                sys.stdout.write("\"\n  \"\\x")
    
        if xorval != None:
            original_opcode = c
            new_opcode = ord(c) ^ ord(xorval[hash_counter])
        else:
            new_opcode = ord(c)

        if fmt=='MASM':
            sys.stdout.write(str(new_opcode))
        elif fmt=='C':
            sys.stdout.write(chr(new_opcode).encode('hex'))
    
        shellcode_counter += 1

        if xorval != None:
            if hash_counter==xorsize - 1:
                hash_counter = 0
            else:
                hash_counter = hash_counter + 1

    if fmt=='C':
        sys.stdout.write("\";")
    sys.stdout.write("\n")
    if fmt=='MASM':
        sys.stdout.write(varname+"len  equ  "+str(shellcode_counter)+"\n")
    elif fmt=='C':
        sys.stdout.write("#define "+varname+"len "+str(shellcode_counter)+"\n")

    sys.stdout.write("\n")

def generate_computername_hash(computername, outformat):
    computernamehash = hashlib.sha1()
    computernamehash.update(computername)
    computernamehash_value = computernamehash.digest()
    comment_character(outformat, "This is the hash of: "+computername+"\n")
    writeout("hashSHA1ComputerName", computernamehash_value, None, None, outformat)

def comment_character(outformat,text):
    if outformat == 'MASM':
        sys.stdout.write("; "+text)
    elif outformat == 'C':
        sys.stdout.write("// "+text)
    return
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Shellcode to C/ASM implant stub converter.')
    parser.add_argument('-c', '--computername', action='store', help='Generate the SHA1 hash of the parameter given (e.g. a computer name)')
    parser.add_argument('-x', '--xor', action='store', help='XOR the shellcode with the hash of the parameter given (e.g. domain name)')
    parser.add_argument('-s', '--shellcode', action='store', help='The filename containing the shellcode.')
    parser.add_argument('-o', '--outputformat', action='store', help='The output format. Can be "C" or "MASM"')
    args = vars(parser.parse_args())

    if 'outputformat' in args and args['outputformat'] != None:
        if args['outputformat'] != 'C' and args['outputformat'] != 'MASM':
            sys.stderr.write("Invalid output format\n")
            sys.exit(1)
    else:
        sys.stderr.write("Invalid output format\n")
        sys.exit(1)
    
    if 'computername' in args and args['computername'] != None:
        generate_computername_hash(args['computername'], args['outputformat'])

    if 'shellcode' in args and args['shellcode'] != None:
        # Read the shellcode from shellcode.raw
        with open(args['shellcode'], 'rb') as s:
            shellcode = s.read()
            s.close()
        comment_character(args['outputformat'], "Shellcode loaded from: "+args['shellcode']+"\n")

        xor = None
        xorsize = None
        if 'xor' in args and args['xor'] != None and len(args['xor'])>0:
            domain_xor = hashlib.sha1()
            domain_xor.update(args['xor'])
            xor = domain_xor.digest()
            xorsize = domain_xor.digest_size
            comment_character(args['outputformat'], "Shellcode XOR'd with hash of: "+args['xor']+"\n")

        writeout('shellcode', shellcode, xor, xorsize, args['outputformat'])
