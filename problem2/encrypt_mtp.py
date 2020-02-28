
from __future__ import print_function
import sys
import os
from key_gen import generateKey
import base64
import binascii
from BitVector import BitVector

def encrypt(plainText, key):
    min_bvlen = min(len(plainText), len(key))
    return plainText ^ key[:min_bvlen]

def readPlainTextFile(fname):
    plainTexts = list()
    with open(fname, "r") as fpt:
        for pt in fpt.readlines():
            plainTexts.append(pt)
    return plainTexts

def encryptFromFile(ptfile, ctfile):
    if os.path.exists(ptfile):
        plainTexts = readPlainTextFile(ptfile)
    else:
        print("File not found. Try again later")
        sys.exit()
    
    key = None
    with open(ctfile, "w") as ctf:
        key = generateKey(keysize=len(max(plainTexts, key = len) ))
        for pt in plainTexts:
            ptbv = BitVector(textstring = pt)
            encrypted = encrypt(ptbv,key)
            ctf.write(encrypted.get_bitvector_in_hex())
            ctf.write("\n")
    
    print("Your cipher texts is written into file {}".format(ctfile))
    return key.get_bitvector_in_hex()

def encryptFromCmd(pt):
    pt = pt.strip()
    ptbv = BitVector(textstring = pt)
    key = generateKey(keysize=len(pt))
    encrypted = encrypt(ptbv, key)
    print(encrypted.get_bitvector_in_hex())
    return key.get_bitvector_in_hex()

if __name__ == "__main__":
    if sys.version_info[0] == 2:                                             
        input = raw_input

    print("Where is your plain Text available?")
    print("1. In file(plaintext seperated by newlines)")
    print("2. I will provide here only.")
    ch = int(input("Enter choice: "))
    if ch == 1:
        ptfile = input("Enter file name: ")
        ctfile = input("Enter file name of cipher text, where you want to store: ")
        key = encryptFromFile(ptfile, ctfile)
        print("Your key is: {}".format(key))
        print("You can get the key from key.txt")
        with open("key.txt", "w") as kf:
            kf.write(key)

    elif ch == 2:
        pt = input("Input plaintext here: ")
        key = encryptFromCmd(pt)
        print("Your key is: {}".format(key))
        print("You can get the key from key.txt")
        with open("key.txt", "w") as kf:
            kf.write(key)

    else:
        print("Wrong choice!!")
        sys.exit()
