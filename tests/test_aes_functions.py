# test_math_functions.py
 
import unittest
# import the package
import code

from code.aes_functions import *
import json

from base64 import b64encode
from base64 import b64decode

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes
import os.path

 
# Define class to test the program
class TestAESFunctions(unittest.TestCase):
    

    def test_encode_decode_b64(self):
        json_dict_input = {'mode':bytes.fromhex('0A'), 'nonce':bytes.fromhex('00AABBCC'), 'ciphertext':bytes.fromhex('1122334455')}
        
        json_dict_b64 = encode_b64(json_dict_input)
        
        
        self.assertEqual(type(json_dict_b64['mode']), bytes)
        self.assertTrue(len(json_dict_b64['mode']) > 0)
        self.assertEqual(type(json_dict_b64['nonce']), bytes)
        self.assertTrue(len(json_dict_b64['nonce']) > 0)
        self.assertEqual(type(json_dict_b64['ciphertext']), bytes)
        self.assertTrue(len(json_dict_b64['ciphertext']) > 0)
        
        json_dict_decoded = decode_b64(json_dict_b64)
        
        self.assertEqual(type(json_dict_decoded['mode']), bytes)
        self.assertEqual(json_dict_decoded['mode'], bytes.fromhex('0A'))
        self.assertEqual(type(json_dict_decoded['nonce']), bytes)
        self.assertEqual(json_dict_decoded['nonce'], bytes.fromhex('00AABBCC'))
        self.assertEqual(type(json_dict_decoded['ciphertext']), bytes)
        self.assertEqual(json_dict_decoded['ciphertext'], bytes.fromhex('1122334455'))
        
        
        
    
    
    def test_CTR_encdec_func(self):
        data = b"secret"
        key = b'Sixteen byte key'
        #key = get_random_bytes(16)

        result = encrypt_CTR_b(key, data)
        

        pt = decrypt_CTR_b(key, result)
            
        self.assertEqual(pt, b"secret")
        
    def test_pack_unpack(self):
        
        data_dict = {'mode':bytes.fromhex('0044824D10'), 'nonce':bytes.fromhex('0011223344556677'), 'ciphertext':bytes.fromhex('1122')}
        self.assertEqual(len(data_dict['mode']), 5)
        self.assertEqual(len(data_dict['nonce']), 8)
        
        config = [('mode', 5), ('nonce', 8), ('ciphertext', None)]
        
        data_packed = pack(data_dict, config)
        self.assertEqual(type(data_packed), bytes)
        self.assertTrue(len(data_packed) > 0)
        
        data_unpacked = unpack_b(data_packed, config)
        
        self.assertEqual(data_unpacked['mode'], data_dict['mode'])
        self.assertEqual(data_unpacked['nonce'], data_dict['nonce'])
        self.assertEqual(data_unpacked['ciphertext'], data_dict['ciphertext'])
        
    def test_pack_unpack2(self):
        
        data_dict = {'mode':bytes.fromhex('0044824D10'), 'nonce':bytes.fromhex('0011223344556677'), 'ciphertext':bytes.fromhex('1122')}
        self.assertEqual(len(data_dict['mode']), 5)
        self.assertEqual(len(data_dict['nonce']), 8)
        
        config = [('nonce', 8), ('ciphertext', None)]
        
        data_packed = pack(data_dict, config)
        self.assertEqual(type(data_packed), bytes)
        self.assertEqual(len(data_packed), 10)#sum of nonce and ciphertext 8+2
        
        data_unpacked = unpack_b(data_packed, config)
        
        with self.assertRaises(Exception):
            data_unpacked['mode']
        self.assertEqual(data_unpacked['nonce'], data_dict['nonce'])
        self.assertEqual(data_unpacked['ciphertext'], data_dict['ciphertext'])
        
    def test_CTR_encdec_rand(self):
        data = b"secret"
        
        key = get_random_bytes(16)

        result = encrypt_CTR_b(key, data)
        
        pt = decrypt_CTR_b(key, result)
            
        self.assertEqual(pt, b"secret")
    def test_CTR_encdec_types(self):
        data = b"secret"
        key = b'Sixteen byte key'

        result = encrypt_CTR_b(key, data)
        
        self.assertEqual(type(result['ciphertext']), bytes)
        self.assertEqual(type(result['mode']), bytes)
        self.assertEqual(type(result['nonce']), bytes)
        
        pt = decrypt_CTR_b(key, result)
        
        self.assertEqual(type(pt), bytes)
        self.assertEqual(pt, data)

        
        
    def test_loadKey(self):
        #assume base 16 Encoding
        path_key = "testkey.txt"
        key = loadKey(path_key)
        
        self.assertEqual(type(key), bytes)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, bytes.fromhex("8c1ac62f38d439f493dd99d73f6c3343"))
        
        
    def test_O(self):
        path = "msg2.txt"
        
        self.assertTrue(os.path.isfile(path))
        content = readfile(path, "rb")
        
        k = derive_Key("AAAA")
        
        
    def test_filecreation(self):
        
        path = "msg1.txt"
        self.assertFalse(os.path.isfile(path))
        
        with open(path, 'wb') as opened_file:
            opened_file.write(b'Merry Christmas')
        
        self.assertTrue(os.path.isfile(path))
        
        content = readfile(path, "rb")
        self.assertEqual(content, b'Merry Christmas')
        
        os.remove(path) 
        
        
        
    def test_filecreation_func(self):
        key = bytes.fromhex("8c1ac62f38d439f493dd99d73f6c3343")
        content = b'Merry Christmas'
        path = "msg2.txt"
        
        path_enc = path+".enc"
        
        c = encrypt_CTR_b(key, content)
        
        
        write_to_file(path_enc, c)
        self.assertTrue(os.path.isfile(path_enc))
        
        
        f = open(path_enc, "rb")
        content = f.read()
        f.close()
        
        
        self.assertEqual(type(content), bytes)
        pt = unpack_b(content)
        pt = decrypt_CTR_b(key, pt)
        
        self.assertEqual(pt, b'Merry Christmas')
        os.remove(path_enc)
        
    def test_derive_Key(self):
        passphrase = "geheim"
        key = derive_Key(passphrase)
        self.assertEqual(len(key), 32)
 
if __name__ == '__main__':
    unittest.main()
