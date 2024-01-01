from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from base64 import b64encode
from base64 import b64decode

import argparse
from math_functions import *

import os.path
import errno
from os import strerror

def parse_args():
    parser = argparse.ArgumentParser(
                    prog='plainaes',
                    description='Ecrypts with aes via diffrent modes, ',
                    epilog='')

    parser.add_argument('-in',  dest='inputfile', default=None)
    parser.add_argument('-out', dest='outputfile', default=None)
    parser.add_argument('-a', '-base64', action='store_true', dest='humanreadable')
    parser.add_argument('-e', action='store_true', dest='enc')
    parser.add_argument('-d', action='store_true', dest='dec' )
    parser.add_argument('-pass', dest='passarg')
    parser.add_argument('-key', dest='keyarg')
    
    args = parser.parse_args()
    
    #encryption is the default
    if args.enc == False and args.dec == False:
        args.enc = True
    if args.enc == True  and args.dec == True:
        raise Exception("Error -e and -d spesified")
    if not args.keyarg and not args.passarg:
        raise Exception("No key nor password source specefied")
    return args

if __name__ == '__main__':
    args = parse_args()
    
    if args.passarg:
        if args.passarg.startswith("file:"):
            path = args.passarg[5:]
            password = readfile(path, "r")
            print(password)
        if args.passarg.startswith("pass:"):
            password = args.passarg[5:]
            print(password)
    #assumed hex encoding        
    key = None
    if args.keyarg:
        if args.keyarg.startswith("file:"):
            path = args.keyarg[5:]
            key = loadKey(path)
        if args.keyarg.startswith("key:"):
            
            key = parsekey(args.keyarg[4:])
            
    
    
    if not args.inputfile:
        raise Exception("no input specified")
    
    #check files
    if not os.path.isfile(args.inputfile):
        raise FileNotFoundError(
            errno.ENOENT, strerror(errno.ENOENT), args.inputfile)
    
    
    if args.outputfile and os.path.isfile(args.outputfile):
        raise Exception("Output file already exists")
    
    args.inputcontent = readfile(args.inputfile, "rb")
    
    #decodeding nedded before decrypting
    if args.humanreadable and args.dec:
        args.inputcontent = b64decode(args.inputcontent)
    
    #assume that input and outputs are bytes
    args.outputcontent = None
    if args.enc:
        ciphertext_dict = encrypt_CTR_b(key, args.inputcontent)
        ciphertext = pack(ciphertext_dict)
        args.outputcontent = ciphertext
    if args.dec:
        ciphertext_dict = unpack(args.inputcontent)
        plaintext = decrypt_CTR_b(key, ciphertext_dict)
        args.outputcontent = plaintext
    
    
    
    #encode in b64 after encrypting
    if args.humanreadable and args.enc:
        args.outputcontent = b64encode(args.outputcontent).decode('utf-8')
        
    #check outputfile
    if args.outputfile:
        pass#TODO do write file
    else:
        print(args.outputcontent)
    
    