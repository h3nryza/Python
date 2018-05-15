#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import pyqrcode
from pyzbar.pyzbar import decode
from PIL import Image
import argparse

class QR(object):

    def createQR(self, text):
        self.qrCode = pyqrcode.create(text)

    def display(self):
        print (self.qrCode.terminal())

    def svg(self, path):
        self.qrCode.svg(path, scale=8)

    def png(self, path):
        self.qrCode.png(path, scale=8)

    def decodeQR(self, path):
        dec = decode(Image.open(path))
        print(dec[0][0])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', type=str, dest='user_input', help='Input, please use -i="test"')
    parser.add_argument('-o', '--output', type=str, dest='output_location',
                        help='Output as png, please use -o="path.tag"')
    parser.add_argument('-e', '-encode',dest='encode', action='store_true', help='Create QR Code')
    parser.add_argument('-d', '--decode', dest='decode', action='store_true', help='Decode QR Code')
    parser.add_argument('-s', '--svg',dest='svg', action='store_true', help='Output as svg')
    parser.add_argument('-p', '--png',dest='png', action='store_true', help='Output as png')
    args = parser.parse_args()

    q = QR()

    if args.encode == True:
        Uin = args.user_input
        Uout = args.output_location
        q.createQR(Uin)
        if args.svg == True:
            q.svg(Uout)
        if args.png == True:
            q.png(Uout)

    if args.decode:
        Uout = args.output_location
        q.decodeQR(Uout)
