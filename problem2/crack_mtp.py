#!/usr/bin/env python
# crack_mtp.py

__author__ = "Jai Singhal"
__copyright__ = "Copyright Feb, 2020"
__version__ = "1.0.0"
__maintainer__ = "Jai Singhal"
__email__ = "h20190021@pilani.bits-pilani.ac.in"
__website__ = "http://jai-singhal.github.io"
__github_repo__ = "https://github.com/jai-singhal/encrypt-decrypt"

"""
Space := ord(" ") # utf-8 or ASCII val of space: 32

Space XOR [.] = [.]
Space XOR Space = 0
[.] XOR [.] = 0
[.] XOR [.] = [.]
**
X XOR Space = x; where X = [A-Z], x = [a-z] and vice versa
ord("A")^ord(" ") = ord("A")
**
k ^ pi = ci
"""
# TODO: change the CT

import string
from BitVector import BitVector
import sys
import os
from pprint import pprint

class CrackMTP(object):
    def __init__(self, *args, **kwargs):
        self.SPACE_ASCII = ord(" ")
        self.ciphertexts = list()
        self.key = list()
        self.threshold = 0.85

    """
    Check for space, i.e, 0
    """
    @staticmethod
    def is_space(ch):
        # returns true if ord(char) is 0
        return True if ord(ch) == 0x00 else False

    """
    Check for char is ascii character
    """
    @staticmethod
    def is_ascii(ch):
        # returns true if ord(char) is in ascii
        return True if ch in string.ascii_letters else False
    

    """
    Xor the two bitvectors
    """
    @staticmethod
    def xor(s1, s2):
        # return xor of two bitvectors
        min_bvlen = min(len(s1), len(s2))
        return s1[:min_bvlen] ^ s2[:min_bvlen]


    """
    Returns bitvector of cipher read by file
    """
    def read_ciphers(self, fname):
        ciphertexts = list()
        with open(fname, "r") as ctf:
            for ct in ctf.readlines():
                ct = ct.strip(" \n\t")
                ciphertexts.append(BitVector(hexstring = ct))
        return ciphertexts

    """
    Main Function that takes file name of cipher text and key from orcale_paddng_attack,
    and return the plain text.
    Computes possible spaces in the text.
    """
    def crack_hrd(self, ciphers):
        key = [None for _ in range(len(ciphers[0])//8)]
        for c1 in ciphers:
            spaceCounter = dict()
            for c2 in ciphers:
                if c1 != c2:
                    xored = self.xor(c1, c2)
                    for index, char in enumerate(xored.get_bitvector_in_ascii()):
                        # if space or any printable char
                        if self.is_space(char) or self.is_ascii(char):
                            if index not in spaceCounter.keys():
                                spaceCounter[index] = 1
                            else:
                                spaceCounter[index] += 1


            for index, count in spaceCounter.items():
                # if count == len(ciphers) - 1:
                if count > len(ciphers)*self.threshold:
                    # pi ^ ci = key; pi = space
                    outer_c = c1.get_bitvector_in_ascii()
                    key[index] = self.SPACE_ASCII ^ ord(outer_c[index])
        return key

    """
    Main function, which calls crack_hrd for cipher text,
    reduces the min length cipher, to get the plain text from big ciphers.
    """
    def spacing_mtp_attack(self, ctfile):
        
        self.ciphertexts = self.read_ciphers(ctfile)
        ciphers = sorted(self.ciphertexts, key = len)
        self.key = list()
        while len(ciphers) > 1:
            last_key = self.crack_hrd(ciphers)
            self.key.extend(last_key[len(self.key):])
            ciphers = ciphers[1:]
        
        plaintexts = []
        for cip in self.ciphertexts:
            pt = str()
            for i, j in zip(cip.get_bitvector_in_ascii(), self.key):
                if j is not None:
                    pt += chr(ord(i) ^ j)
                else:
                    pt += "*"
            plaintexts.append(pt)
        return plaintexts
                

    """
     Writes back the messages decrypted.
    """
    def writeDecryptedPlainText(self, decrypted_msg):
        with open("recoveredtext.txt", "w", newline = "") as wb:
            wb.write("\n".join(decrypted_msg))


if __name__ == "__main__":
    cfname = "ciphertext.txt"
    if sys.version_info[0] == 3:   
        cfname = input("\nEnter filname of cipher text to crack: ")
    else:                                                                         
        cfname = raw_input("\nEnter filname of cipher text to crack: ")

    print("Crack started!!")
    print("Please wait for crack to finish, this will take few seconds...")

    c = CrackMTP()
    decrypted_msg = c.spacing_mtp_attack(cfname)
    c.writeDecryptedPlainText(decrypted_msg)
        
    print(f"\nPlain text is written into recoveredtext.txt file.\n\n")
