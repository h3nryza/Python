#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto import Random
import base64
import argparse



class hasher(object):
    __dict__ = '''Provides hash algos'''

    def md(self, input):
        md = MD5.new()
        md.update(args.Input)
        return (md.hexdigest())

    def sha256(self, input):
        sh = SHA256.new()
        sh.update(args.Input)
        return (sh.hexdigest())

    def sha512(self, input):
        sh = SHA512.new()
        sh.update(args.Input)
        return (sh.hexdigest())


class crypto(object):
    __dict__ = '''Provides encryption and decryption'''

    def __init__(self):
        self.BLOCK_SIZE = 16

    def encrypt_aes(self,input, key):
        IV = Random.new().read(self.BLOCK_SIZE)
        IV_base=base64.b64encode(IV)
        aes = AES.new(key[0:16], AES.MODE_CFB, IV)
        aes_encryption = IV_base + base64.b64encode(aes.encrypt(input))
        return aes_encryption

    def decrypt_aes(self, input, key):
        IV = base64.b64decode(input[:24])
        aes = AES.new(key[0:16], AES.MODE_CFB, IV)
        return aes.decrypt(base64.b64decode(input[23:]))

if __name__ == "__main__" :
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', dest='Input', help='Input for hash, if any')
    parser.add_argument('-f', '--file', dest='File_flag', action='store_true', help='Flag Option if input is a file')
    parser.add_argument('-ha', '--hash', dest='hash', action='store_true', help='Flag for Hash Output')
    parser.add_argument('-ae', '--aes_encryption', dest='aes_encryption_flag',
                        action='store_true', help='Flag for AES Encryption')
    parser.add_argument('-ad', '--aes_decryption', dest='aes_decryption_flag',
                        action='store_true', help='Flag for AES Decryption')
    parser.add_argument('-ak', '--aes_key', dest='aes_key', help='Key for AES Encyption.Length of atleast 16')
    args = parser.parse_args()


    if args.File_flag == True:
        input = open(args.Input, 'rb').read()
    else:
        input = str(args.Input)

    if args.hash == True:
        h = hasher()
        md = h.md(input)
        print('MD5 Hash => {}'.format(md))

        sh256 = h.sha256(input)
        print('SHA256 Hash => {}'.format(sh256))

        sh512 = h.sha512(input)
        print('SHA512 Hash => {}'.format(sh512))

    if args.aes_encryption_flag == True:
        e = crypto()
        aes_encrypt = e.encrypt_aes(input, args.aes_key)
        print('AES Encryption => {}'.format(aes_encrypt))

    if args.aes_decryption_flag == True:
        d = crypto()
        aes_decrypt = d.decrypt_aes(input, args.aes_key)
        print('AES Decryption => {}'.format(aes_decrypt))
