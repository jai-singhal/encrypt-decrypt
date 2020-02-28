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

import collections
import string
from BitVector import BitVector
import sys
import re
import os
from pprint import pprint

class CrackMTP(object):
    def __init__(self, *args, **kwargs):
        self.SPACE_ASCII = ord(" ")
        self.ciphertexts = list()
        self.key = list()
        self.threshold = 0.85

    def is_space(self, ch):
        return True if ord(ch) == 0x00 else False

    def is_ascii(self, ch):
        return True if ch in string.ascii_letters else False
    
    def xor(self, s1, s2):
        min_bvlen = min(len(s1), len(s2))
        return s1[:min_bvlen] ^ s2[:min_bvlen]

    def count_spaces(self, txt):
        counter = collections.Counter()
        for index, char in enumerate(txt):
            if self.is_space(char) or self.is_ascii(char):
                counter[index] += 1
        return counter

    def read_ciphers(self, fname):
        ciphertexts = list()
        with open(fname, "r") as ctf:
            for ct in ctf.readlines():
                ct = ct.strip(" \n\t")
                ciphertexts.append(BitVector(hexstring = ct))
        return ciphertexts

    def spaces_count(self, text):
        counter = collections.Counter()
        for index, char in enumerate(text):
            # if space or any printable char
            if self.is_space(char) or self.is_ascii(char):
                counter[index] += 1
        return counter

    def crack_hrd(self, ciphers):
        key = [None for _ in range(len(ciphers[0])//8)]
        for i1, c1 in enumerate(ciphers):
            counter = collections.Counter()
            for i2, c2 in enumerate(ciphers):
                if i1 != i2:
                    xored = self.xor(c1, c2)
                    counter.update(
                        self.spaces_count(xored.get_bitvector_in_ascii())
                    )
                    
            for index, count in counter.items():
                # if count == len(ciphers) - 1:
                if count > len(ciphers)*self.threshold:
                    # pi ^ ci = key; pi = space
                    outer_c = c1.get_bitvector_in_ascii()
                    key[index] = self.SPACE_ASCII ^ ord(outer_c[index])
        return key

    def crack(self, ctfile):
        
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
                    pt += "_"
            plaintexts.append(pt)
        return plaintexts
                

if __name__ == "__main__":
    cfname = "ciphertext.txt"
    if sys.version_info[0] == 3:   
        cfname = input("\nEnter filname of cipher text to crack: ")
    else:                                                                         
        cfname = raw_input("\nEnter filname of cipher text to crack: ")

    print("Crack started!!")
    print("Please wait for crack to finish, this will take few seconds...")
    c = CrackMTP()
    decrypted_msg = c.crack(cfname)

    with open("recoveredtext.txt", "w") as wb:
        wb.write("\n".join(decrypted_msg))
    print(f"\n\nPlain text is written into recoveredtext.txt file.")
