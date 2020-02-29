#!/usr/bin/env python
# decrypt_mtp.py

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
from BitVector import BitVector

def decrypt(cipherText, key):
    min_bvlen = min(len(cipherText), len(key))
    return cipherText ^ key[:min_bvlen]

def readcipherTextFile(fname):
    cipherTexts = list()
    with open(fname, "r") as fpt:
        for ct in fpt.readlines():
            cipherTexts.append(ct)
    return cipherTexts

def decryptFromFile(ctfile, ptfile, keyfile):
    if os.path.exists(ctfile):
        cipherTexts = readcipherTextFile(ctfile)
    else:
        print("Cipher File not found. Try again later")
        sys.exit()

    if os.path.exists(keyfile):
        key = open(keyfile).read()
    else:
        print("Key File not found. Try again later")
        sys.exit()

    plaintexts = list()
    keybv = BitVector(hexstring = key)

    for ct in cipherTexts:
        ctbv = BitVector(hexstring = ct.strip(" \n\t"))
        decrypted = decrypt(ctbv, keybv)
        plaintexts.append(decrypted)

    with open(plainfile, "w", newline="") as kf:
        for pt in plaintexts:
            pt = pt.getTextFromBitVector()
            kf.write(pt)

    print("Your cipher texts is written into file {}".format(ptfile))
    return plaintexts

def decryptFromCmd(ct, key):
    ct = ct.strip()
    ctbv = BitVector(hexstring = ct)
    key = BitVector(hexstring = key)
    pt = decrypt(ctbv, key)
    pt = pt.getTextFromBitVector()
    return pt

if __name__ == "__main__":
    if sys.version_info[0] == 2:                                             
        input = raw_input

    print("Where is your cipher Text available?")
    print("1. In file(ciphertext seperated by newlines)")
    print("2. I will provide here only.")
    ch = int(input("Enter choice: "))
    if ch == 1:
        ctfile = input("Enter file name where cipher stored: ")
        keyfile = input("Enter file name of key: ")
        plainfile = input("Enter file name where you want to store plaintext: ")
        try:
            plaintexts = decryptFromFile(ctfile, plainfile, keyfile)
        except Exception as e:
            print("Please provide the correct hex")
            print(f"Exception caught: {type(e).__name__}")

    elif ch == 2:
        ct = input("Input ciphertext here: ")
        key = input("Input key here: ")
        try:
            pt = decryptFromCmd(ct, key)
            print(f"Your plaintext is: {pt}")
        except Exception as e:
            print("Please provide the correct hex")
            print(f"Exception caught: {type(e).__name__}")

    else:
        print("Wrong choice!!")
        sys.exit()
