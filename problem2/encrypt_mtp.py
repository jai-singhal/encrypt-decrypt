
#!/usr/bin/env python
# encrypt_mtp.py

__author__ = "Jai Singhal"
__copyright__ = "Copyright Feb, 2020"
__version__ = "1.0.0"
__maintainer__ = "Jai Singhal"
__email__ = "h20190021@pilani.bits-pilani.ac.in"
__website__ = "http://jai-singhal.github.io"
__github_repo__ = "https://github.com/jai-singhal/encrypt-decrypt"


import sys
import os
from key_mtp import generateKey
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
            if pt == "\n":
                continue
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
    print("Your cipher text is: ", encrypted.get_bitvector_in_hex())

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

        try:
            key = encryptFromFile(ptfile, ctfile)
            print("\nYou can get the key from key.txt !!\n")
            with open("key.txt", "w") as kf:
                kf.write(key)
        except Exception as e:
            print(f"Exception caught: {type(e).__name__}")

    elif ch == 2:
        pt = input("Input plaintext here: ")
        try:
            key = encryptFromCmd(pt)
            print("Your key is: {}".format(key))
        except Exception as e:
            print(f"Exception caught: {type(e).__name__}")
    else:
        print("Wrong choice!!")
        sys.exit()
