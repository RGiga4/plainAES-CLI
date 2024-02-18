from Crypto.Cipher import AES

from base64 import b64encode
from base64 import b64decode

import argparse


try:
    from code.aes_functions import *
except ImportError:
    from aes_functions import *

import os.path
import errno
import getpass
from os import strerror
import sys

#wrapper for input and output for better testing
def w_input(*args):
    return input(*args)
def w_print(*args):
    print(*args)
def dummy_print(*args):
    pass


# The return object from parse_args is used to store additional information
#like the key, ciphertext, plaintext, filenames, ect in it.

def parse_args(sys_argv):
    
    parser = argparse.ArgumentParser(
                    prog='plainaes',
                    description='Encrypts with aes via diffrent modes, ',
                    epilog='')

    parser.add_argument('-a', '-base64', action='store_true', dest='humanreadable')
    parser.add_argument('-e', action='store_true', dest='enc')
    parser.add_argument('-d', action='store_true', dest='dec' )
    parser.add_argument('-pass', dest='passarg')
    parser.add_argument('-key', dest='keyarg')
    parser.add_argument('-in',  dest='inputfile', default=None)
    parser.add_argument('-out', dest='output', default=None)
    parser.add_argument('-pout', action='store_true', dest='printout', default=False)
    parser.add_argument('-textin', action='store_true', dest='textstdin', default=False)
    parser.add_argument('-noheader', action='store_true', dest='noheader')
    parser.add_argument('-prompt', action='store_true', dest='textprompt')
    
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
            key = None
            if args.textprompt:
                key = getpass.getpass(prompt = "Key in hex:")
            else:
                key = getpass.getpass()
            key = parsekey(key)
            args.key = key
    else:
        args.key = None
    
    #assumed and earler checked that key or password exists
    if not args.key:
        args.key = derive_Key(args.password)
        
    
    
def handle_input(args):
    #input  handling
    if not args.inputfile and not args.textstdin:
        raise Exception("no input specified")
    
    if args.inputfile:    
        #check files
        if not os.path.isfile(args.inputfile):
            raise FileNotFoundError(
                errno.ENOENT, strerror(errno.ENOENT), args.inputfile)
    
    
        args.inputcontent = readfile(args.inputfile, "rb")
    if args.textstdin:
        if args.textprompt:
            print("Please enter the message:\n")
        args.inputcontent = w_input().encode('utf-8')
        
    
def creat_config(args):
    
    config = []
    
    if hasattr(args, 'noheader') and args.noheader:
        #Default config mode-nonce-ciphertext
        config = [('nonce', 8), ('ciphertext', None)]
    else:
        config = [('mode', 5), ('nonce', 8), ('ciphertext', None)]
    
    #None stands for data until the end
    args.config = config
    
def handle_enc_dec(args):
    #handles encoding, decoding, encryptingm decrypting
    
    creat_config(args)
    
    #decodeding nedded before decrypting
    if args.humanreadable and args.dec:
        args.inputcontent = b64decode(args.inputcontent)
    
    #assume that input and outputs are bytes
    #and encrypting
    
    if args.enc:
        ciphertext_dict = encrypt_CTR_b(args.key, args.inputcontent)
        ciphertext_pack = pack(ciphertext_dict, args.config)
        args.outputcontent = ciphertext_pack
        args.encoding = "bytes"
    if args.dec:
        ciphertext_dict = unpack_b(args.inputcontent, args.config)
        plaintext = decrypt_CTR_b(args.key, ciphertext_dict)
        args.outputcontent = plaintext
        args.encoding = "all"
    
    #encode in b64 after encrypting
    if args.humanreadable and args.enc:
        args.outputcontent = b64encode(args.outputcontent)
        args.encoding = "b64"
        
def handle_output(args):
    
    
    if args.output:
    
        path = args.output
        
        with open(path, 'wb') as opened_file:
            opened_file.write(args.outputcontent)
            
    if args.printout:
        
        if args.encoding == "b64":
            if args.textprompt:
                print("base64 message:\n")
            w_print(args.outputcontent.decode('utf-8'))
        if args.encoding == "bytes" or args.encoding == "all":
            try:
                w_print(args.outputcontent.decode('utf-8'))
            except UnicodeDecodeError:
                if args.textprompt:
                    print("hex message:\n")
                    w_print(args.outputcontent.hex())
                    print("bytes message:\n")
                sys.stdout.buffer.write(args.outputcontent)
                
    
    
    
