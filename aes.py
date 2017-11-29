#!/usr/bin/python

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import argparse
from argparse import RawTextHelpFormatter
import logging

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
parser.add_argument('--password',help='', default=False)
parser.add_argument('--message',help='',default=False)
parser.add_argument('--password-file',help='', default=False)
parser.add_argument('--message-file',help='',default=False)
parser.add_argument('--encrypt', action='store_true',default=False)
parser.add_argument('--decrypt', action='store_true',default=False)
args = parser.parse_args()
password = args.password
message = args.message
password_file = args.password_file
message_file = args.message_file
encrypt = args.encrypt
decrypt = args.decrypt

if password_file:
    password = open(password_file, 'r').read()

if message_file:
    message = open(message_file, 'r').read()

if password:
    if message:
        if encrypt and not decrypt:
            encryptor = AESCipher(password)
            print(encryptor.encrypt(message))
        elif not encrypt and decrypt:
            encryptor = AESCipher(password)
            print(encryptor.decrypt(message))
    else:
        logging.warning("message is missing")
else:
    logging.warning("password is missing")
