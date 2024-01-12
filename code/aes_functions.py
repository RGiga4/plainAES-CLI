from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512

from base64 import b64encode
from base64 import b64decode

import json
# math_functions.py


def encrypt_CTR_b(key, data):
    #input: key 32 bytes and bytes data
    #nonce is 8 byte default, can be changed
    #data as bytes
    #output: dict with bytes
    cipher = AES.new(key, AES.MODE_CTR)

    ct_bytes = cipher.encrypt(data)

    nonce = cipher.nonce

    result_dict = {'mode':bytes.fromhex('0044824D10'), 'nonce':nonce, 'ciphertext':ct_bytes}
    return result_dict
    

def decrypt_CTR_b(key, json_dict):
#input key 32 bytes
#json_dict, containg nonce and ciphertext as bytes
    pt = None
    try:

        nonce = json_dict['nonce']

        ct = json_dict['ciphertext']

        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

        pt = cipher.decrypt(ct)

        #print("The message was: ", pt)

    except (ValueError, KeyError):

        print("Incorrect decryption")
        
    return pt


def encode_b64(json_dict):
    #encodes specaial elemnts in the dict into bytes b64 encoding
    if 'mode' in json_dict:
        json_dict['mode'] = b64encode(json_dict['mode'])
    json_dict['nonce'] = b64encode(json_dict['nonce'])
    json_dict['ciphertext'] = b64encode(json_dict['ciphertext'])#.decode('utf-8')
    
    return json_dict

def decode_b64(json_dict):
    #decodes specaial elemnts in the dict from bytes b64 encoding to bytes
    if 'mode' in json_dict:
        json_dict['mode'] = b64decode(json_dict['mode'])
    json_dict['nonce'] = b64decode(json_dict['nonce'])
    json_dict['ciphertext'] = b64decode(json_dict['ciphertext'])
    
    return json_dict
def pack(data):
    #print(data['mode'], data['nonce'], data['ciphertext'])
    return data['mode']+ data['nonce']+ data['ciphertext']
    

def unpack_b(packed_data):
    mode_size = 5
    nonce_size = 8
    result_dict = {}
    
    result_dict["mode"] = packed_data[0 : mode_size]
    result_dict["nonce"] = packed_data[mode_size : mode_size+nonce_size]
    result_dict["ciphertext"] = packed_data[mode_size+nonce_size : ]
    #print(result_dict)
    return result_dict

def readfile(path, opcode):
    
    f = open(path, opcode)
    content = f.read()
    f.close()
    
    #if content[-1] == 10 or content[-1] == '\n':#byte compare or string compare
    #    content = content[:-1]
    return content
    
def derive_Key(passphrase):
    iterations = 10**4
    salt = bytes.fromhex("47ba2fe75d760c4ff1c42b6394150fd9")
    key_material = PBKDF2(passphrase, salt, iterations, hmac_hash_module=SHA512)
    key = key_material[:32]
    return key

def unlockKeyfile(passphrase, path_file):
    pass
    
def parsekey(key_string):
#assume hex encoding
    key = bytes.fromhex(key_string[0:32])#TODO 2 error handling
    return key
def loadKey(path_file):
#assume hex encoding
#IDEA:maybe header handling
    f = open(path_file, "r")
    line = f.readline()
    
    f.close()
    key = parsekey(line)
    return key
    
def write_to_file(pathfile, data_dict):
#TODO error code handling
#write the dict to a file
    pack_data = pack(data_dict)
    encrypted_file = open(pathfile, "wb")
    encrypted_file.write(pack_data)
    encrypted_file.close()
def load_from_file(path_file):
#load the dict from a file
    packed_data = readfile(path, "rb")
    result = unpack_b(packdata)
    
    return result
