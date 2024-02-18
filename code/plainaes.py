from Crypto.Cipher import AES


from aes_functions import *
from handler import *
import sys

if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    handle_password_key(args)
    handle_input(args)
    handle_enc_dec(args)
    handle_output(args)
    
