from Crypto.Cipher import AES

from base64 import b64encode
from base64 import b64decode

import argparse

#from aes_functions import *
from code.aes_functions import *

import os.path
import errno
import getpass
from os import strerror


# The return object from parse_args is used to store additional information
#like the key, ciphertext, plaintext, filenames, ect in it.

def parse_args(sys_argv):
    
    parser = argparse.ArgumentParser(
                    prog='plainaes',
                    description='Encrypts with aes via diffrent modes, ',
                    epilog='')

    parser.add_argument('-in',  dest='inputfile', default=None)
    parser.add_argument('-out', dest='output', default=None)
    parser.add_argument('-a', '-base64', action='store_true', dest='humanreadable')
    parser.add_argument('-e', action='store_true', dest='enc')
    parser.add_argument('-d', action='store_true', dest='dec' )
    parser.add_argument('-pass', dest='passarg')
    parser.add_argument('-key', dest='keyarg')
    
    args = parser.parse_args(sys_argv)
    
    #encryption is the default
    if args.enc == False and args.dec == False:
        args.enc = True
    if args.enc == True  and args.dec == True:
        raise Exception("Error -e and -d spesified")
    if not args.keyarg and not args.passarg:
        raise Exception("No key nor password source specefied")
    return args
    
def handle_password_key(args):
    #specify password or key, both not both
    #file: option or stdin stdout
    #for the -key key: option hex encoding is assumed
    #if the key is loaded from a file hex encoding is assumed also hear (myabe change later)
    
    if args.passarg:
        if args.passarg.startswith("file:"):
            path = args.passarg[5:]
            password = readfile(path, "r")
            
            args.password = password
        if args.passarg.startswith("pass:"):
            password = args.passarg[5:]
            
            args.password = password
        if args.passarg.startswith("stdin"):
            password = getpass.getpass()
            
            args.password = password
            
    else:
        args.password = None
        
    #assumed hex encoding        
    
    if args.keyarg:
        if args.keyarg.startswith("file:"):
            path = args.keyarg[5:]
            key = loadKey(path)
            args.key = key
        if args.keyarg.startswith("key:"):
            
            key = parsekey(args.keyarg[4:])
            args.key = key
        if args.keyarg.startswith("stdin"):
            key = getpass.getpass(prompt = "Key in hex: ")
            key = parsekey(key)
            args.key = key
    else:
        args.key = None
    
    if args.key:
        pass#TODO derive key form password
    
    
def handle_input(args):
    
    #input output handling
    if not args.inputfile:
        raise Exception("no input specified")
    
    #check files
    if not os.path.isfile(args.inputfile):
        raise FileNotFoundError(
            errno.ENOENT, strerror(errno.ENOENT), args.inputfile)
    
    
    args.inputcontent = readfile(args.inputfile, "rb")
    
def handle_enc_dec(args):
    #handles encoding, decoding, encryptingm decrypting
    
    #decodeding nedded before decrypting
    if args.humanreadable and args.dec:
        args.inputcontent = b64decode(args.inputcontent)
    
    #assume that input and outputs are bytes
    #and encrypting
    
    
    if args.enc:
        ciphertext_dict = encrypt_CTR_b(args.key, args.inputcontent)
        ciphertext_pack = pack(ciphertext_dict)
        args.outputcontent = ciphertext_pack
    if args.dec:
        ciphertext_dict = unpack(args.inputcontent)
        plaintext = decrypt_CTR_b(key, ciphertext_dict)
        args.outputcontent = plaintext
    
    #encode in b64 after encrypting
    if args.humanreadable and args.enc:
        args.outputcontent = b64encode(args.outputcontent)#
        
def handle_output(args):
    
    
    if args.output:
        if args.output.startswith("file:"):
            path = args.output[5:]
            if os.path.isfile(path):
                raise Exception("Output file already exists")
            
            with open(path, 'wb') as opened_file:
                opened_file.write(args.outputcontent)
            
        if args.output.startswith("stdout"):
            print(args.outputcontent.decode('utf-8'))
    
    
    
