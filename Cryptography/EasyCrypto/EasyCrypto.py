from __future__ import print_function
import base64
from Crypto.Cipher import AES
from Crypto import Random
from optparse import OptionParser
from pkcs7 import PKCS7Encoder

class EasyCrypto(object):
    __doc__ = '''This library is for making an Easy AES encryption with self created key'''

    BS = 128

    def pad(self,s):
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)

    def unpad(self,s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, data):
        encoder = PKCS7Encoder()
        key = (Random.get_random_bytes(32))
        data = encoder.encode(data)
        iv = Random.new().read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        Encoded_data = base64.b64encode(cipher.encrypt(data))

        b64Key = base64.b64encode(key).encode("utf-8")
        b64iv = base64.b64encode(iv).encode("utf-8")

        return b64Key + b64iv + Encoded_data

    def decrypt(self, data):
        b64key = data[:44]
        b64iv = data[44:68]
        b64encrypted = data[68:]

        key = base64.b64decode(b64key)
        iv = base64.b64decode(b64iv)
        encrypted = base64.b64decode(b64encrypted)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        Decoded_data = self.unpad(cipher.decrypt(encrypted))
        if Decoded_data[-2:] == "==":
            return(base64.b64decode(Decoded_data))
        return Decoded_data

    def sendToFile(self, inData, outData):
        data = open(inData, 'rb').read()
        fileOut = open(outData, 'w')
        fileOut.write(self.encrypt(data))
        fileOut.close()

    def getFromFile(self, inData, outData):
        data = open(inData, 'r').read()
        fileOut = open(outData, 'wb')
        fileOut.write(self.decrypt(data))
        fileOut.close()


if __name__ == '__main__':
    parser = OptionParser()
    parser.set_description('Easy Encryption')
    parser.add_option("-i", "--input", dest='data', help="[REQUIRED] Data to be encrypted / decrypted")
    parser.add_option("-e", "--encrypt", action="store_true", dest="encrypt", help="Flag for encryption")
    parser.add_option("-d", "--decrypt", action="store_true", dest="decrypt", help="Flag for decryption")
    parser.add_option("-f", "--file", action="store_true", dest="input_file", help="Flag for file decrypt / encrypt")
    parser.add_option("-o", "--outFile", dest="outFile", help="File for output")

    (options, args) = parser.parse_args()
    ec = EasyCrypto()

    #String data to encrypt, with output to screen
    if options.encrypt != None and options.outFile == None and options.input_file == None:
        print(ec.encrypt(options.data))
    #String data to decrypt, with output to screen
    if options.decrypt != None and options.outFile == None and options.input_file == None:
        print(ec.decrypt(options.data))

    # String data to encrypt, with output to file
    if  options.encrypt != None and options.outFile != None and options.input_file == None:
        fileOut = open(options.outFile, 'w')
        fileOut.write(ec.encrypt(options.data))
        fileOut.close()
    # String data to decrypt, with output to file
    if options.decrypt != None and options.outFile != None and options.input_file == None:
        fileOut = open(options.outFile, 'w')
        fileOut.write(ec.decrypt(options.data))
        fileOut.close()

    #File data to encrypt, output to screen
    if options.encrypt != None and options.outFile != None:
        data = open(options.data, 'rb').read()
        print(ec.encrypt(data))
    # File data to decrypt, output to screen
    if options.decrypt != None and options.outFile != None:
        data = open(options.data, 'rb').read()
        print(ec.decrypt(data))

    #File data to encrypt, output to file
    if options.encrypt != None and options.outFile != None:
        ec.sendToFile(options.data, options.outFile)
    # File data to decrypt, output to file
    if options.decrypt != None and options.outFile != None:
        ec.getFromFile(options.data,options.outFile)