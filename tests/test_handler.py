# test_math_functions.py
 
import unittest
# import the package
import code

from code.aes_functions import *
from code.handler import *

from base64 import b64encode
from base64 import b64decode

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes
import os.path

import argparse

 
# Define class to test the program
class TestHandler(unittest.TestCase):
    
    
    #Test wether .e .d, set exclusuvly,
    #Eroro if key and password not set
    #correctly loaded key, pass args
    #test falg humanreable for None
    
    def test_parse_args1(self):
        sys_argv = ["-e", "-pass", "stdin"]
        
        args = parse_args(sys_argv)
        
        self.assertEqual(args.enc, True)
        self.assertEqual(args.dec, False)
        self.assertEqual(args.humanreadable, False)
        self.assertIsNotNone(args.passarg)
        self.assertIsNone(args.keyarg)
    def test_parse_args2(self):
        sys_argv = ["-d", "-pass", "stdin"]
        
        args = parse_args(sys_argv)
        
        self.assertEqual(args.enc, False)
        self.assertEqual(args.dec, True)
        self.assertEqual(args.humanreadable, False)
        self.assertIsNotNone(args.passarg)
        self.assertIsNone(args.keyarg)
    def test_parse_args3(self):
        sys_argv = ["-pass", "stdin"]
        
        args = parse_args(sys_argv)
        
        self.assertEqual(args.enc, True)
        self.assertEqual(args.dec, False)
        self.assertEqual(args.humanreadable, False)
        self.assertIsNotNone(args.passarg)
        self.assertIsNone(args.keyarg)
    def test_parse_args4(self):
        sys_argv = ["-e", "-a", "-pass", "stdin"]
        
        args = parse_args(sys_argv)
        
        self.assertEqual(args.enc, True)
        self.assertEqual(args.dec, False)
        self.assertEqual(args.humanreadable, True)
        self.assertIsNotNone(args.passarg)
        self.assertIsNone(args.keyarg)
        
    def test_parse_args5(self):
        sys_argv = ["-e", "-key", "AAAA"]
        
        args = parse_args(sys_argv)
        
        self.assertEqual(args.enc, True)
        self.assertEqual(args.dec, False)
        self.assertEqual(args.humanreadable, False)
        self.assertIsNone(args.passarg)
        self.assertIsNotNone(args.keyarg)
        self.assertEqual(args.keyarg, 'AAAA')
    def test_parse_args6(self):
        sys_argv = ["-e"]
        
        with self.assertRaises(Exception):
            parse_args(sys_argv)
        
    
        
    def test_handle_password_key1(self):
        args = argparse.Namespace()
        args.passarg = None
        args.keyarg = "key:aaaabbbbccccddddffff000011112222"
        
        handle_password_key(args)
        
        self.assertEqual(args.password, None)
        self.assertEqual(args.key, bytes.fromhex("aaaabbbbccccddddffff000011112222"))
    def test_handle_password_key2(self):
        args = argparse.Namespace()
        args.passarg = None
        args.keyarg = "file:input1.txt"
        
        path = "input1.txt"
        with open(path, 'wb') as opened_file:
            opened_file.write(b'aaaabbbbccccddddffff000011112222')#ascii bytes
        
        self.assertTrue(os.path.isfile(path))
        
        handle_password_key(args)
        
        self.assertEqual(args.password, None)
        self.assertEqual(args.key, bytes.fromhex("aaaabbbbccccddddffff000011112222"))
        
        os.remove(path)
        
    def test_handle_password_key3(self):
        args = argparse.Namespace()
        args.passarg = "pass:123456"
        args.keyarg = None
        
        handle_password_key(args)
        
        self.assertEqual(args.password, "123456")
        self.assertIsNotNone(args.key)
        
        
    def test_handle_password_key4(self):
        args = argparse.Namespace()
        args.passarg = "file:input2.txt"
        args.keyarg = None
        
        path = "input2.txt"
        with open(path, 'wb') as opened_file:
            opened_file.write(b'123456')#ascii bytes
        
        self.assertTrue(os.path.isfile(path))
        
        handle_password_key(args)
        
        self.assertEqual(args.password, "123456")
        self.assertIsNotNone(args.key)
        
        os.remove(path)
        
    def test_handle_input(self):
        args = argparse.Namespace()
        args.inputfile = "input3.txt"
        
        path = "input3.txt"
        with open(path, 'wb') as opened_file:
            opened_file.write(b'Hallo')#ascii bytes
        
        self.assertTrue(os.path.isfile(path))
        
        handle_input(args)
        
        self.assertEqual(args.inputcontent, b'Hallo')
        #self.assertEqual(args.key, )
        os.remove(path)
    def test_handle_enc_dec1(self):
        args = argparse.Namespace()
        args.enc = True
        args.dec = False
        args.humanreadable = None
        args.inputcontent = b'hallo'
        args.key = bytes.fromhex("aaaabbbbccccddddffff000011112222")
        
        handle_enc_dec(args)#encryption has random nonce
        
        self.assertIsNotNone(args.outputcontent)
        self.assertTrue(len(args.outputcontent) > 12)
    def test_handle_enc_dec2(self):
        args = argparse.Namespace()
        args.enc = False
        args.dec = True
        args.humanreadable = None
        args.inputcontent = bytes.fromhex("0044824d10487e0477485e64dc8104bf71b3")
        args.key = bytes.fromhex("aaaabbbbccccddddffff000011112222")
        
        handle_enc_dec(args)
        
        self.assertEqual(args.outputcontent, b'hallo')
    def test_handle_enc_dec3(self):
        args = argparse.Namespace()
        args.enc = True
        args.dec = False
        args.humanreadable = True
        args.inputcontent = b'hallo'
        args.key = bytes.fromhex("aaaabbbbccccddddffff000011112222")
        
        handle_enc_dec(args)#encryption has random nonce
        
        self.assertIsNotNone(args.outputcontent)
        self.assertTrue(type(args.outputcontent), bytes)
        self.assertTrue(len(args.outputcontent) > 12)
        #TODO test decryption with encoding 'AESCTRDBz2wbDy0Ns86QMJAv'
        
    def test_handle_enc_dec4(self):
        args = argparse.Namespace()
        args.enc = False
        args.dec = True
        args.humanreadable = True
        args.inputcontent = bytes.fromhex("41455343545244427a3277624479304e733836514d4a4176")
        args.key = bytes.fromhex("aaaabbbbccccddddffff000011112222")
        
        handle_enc_dec(args)
        
        self.assertEqual(args.outputcontent, b'hallo')
    
    def test_handle_output(self):
        args = argparse.Namespace()
        path = "output1.txt"
        args.output = "file:"+path
        args.outputcontent = b'abcdef'
        
        self.assertFalse(os.path.isfile(path))
        
        handle_output(args)
        
        self.assertTrue(os.path.isfile(path))
        
        
        content = readfile(path, "rb")
        self.assertEqual(content, args.outputcontent)
        
        os.remove(path)
 
if __name__ == '__main__':
    unittest.main()
