from __future__ import print_function
import sys
import os
from key_gen import generateKey
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

    with open(plainfile, "w") as kf:
        for pt in plaintexts:
            pt = pt.getTextFromBitVector()
            kf.write(pt)
            kf.write("\n")

    print("Your cipher texts is written into file {}".format(ptfile))
    return plaintexts

def decryptFromCmd(ct, key):
    ct = ct.strip()
    ctbv = BitVector(textstring = ct)
    key = BitVector(hexstring = key)
    pt = decrypt(ctbv, key)
    pt = pt.getTextFromBitVector()
    print(pt)
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
        plaintexts = decryptFromFile(ctfile, plainfile, keyfile)
        

    elif ch == 2:
        ct = input("Input ciphertext here: ")
        key = input("Input key here: ")
        decryptFromCmd(ct, key)
    else:
        print("Wrong choice!!")
        sys.exit()
