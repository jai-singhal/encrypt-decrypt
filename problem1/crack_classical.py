#!/usr/bin/env python
# crack.py

__author__ = "Jai Singhal"
__copyright__ = "Copyright Feb, 2020"
__version__ = "1.0.0"
__maintainer__ = "Jai Singhal"
__email__ = "h20190021@pilani.bits-pilani.ac.in"
__website__ = "http://jai-singhal.github.io"
__github_repo__ = "https://github.com/jai-singhal/encrypt-decrypt"

"""
CBC, or Cipher-Block Chaining
###
###  Input will be key, default key= bits@f463

Space XOR [.] = [.]
Space XOR Space = 0
**X XOR Space = x; where X = [A-Z], x = [a-z] and vice versa**

Given, 
C(i) = C(i-1) ^ P(i) ^ K, where i ∈ [0, NUMB_BLOCKS]
==> C(i-1) ^ C(i) = P(i) ^ K
==> C`(i) = P(i) ^ K
==> P(i) = C`(i) ^ K 

Its in MTP, with each block is encrypted with same key.
We can use space attack, just as we used in other question.
"""

import sys
from BitVector import BitVector
import string
from collections import Counter


BLOCK_THRESHOLD = 30

# can be changed to anything, only first block get affected
PassPhrase = "I want to learn cryptograph and network security"

"""
Method 1:
Space attack in MTP: If cipher text length is more than 180 characters, go for this method. 
"""
class CrackCBCBySpaceAttack(object):
    """
    CLass initializer
    """
    def __init__(self, *args, **kwargs):
        self.SPACE_ASCII = ord(" ")
        self.ciphertexts = list()
        self.key = list()
        self.BLOCKSIZE = 64
        self.numbytes = self.BLOCKSIZE // 8
        self.THRESHOLD = 0.85

    """
    Returns bitvector of passphrase
    """
    def getPassPhrase(self):
        pphrase = BitVector(bitlist = [0]*self.BLOCKSIZE)
        for i in range(0,len(PassPhrase) // self.numbytes):
            textstr = PassPhrase[i*self.numbytes:(i+1)*self.numbytes]
            pphrase ^= BitVector( textstring = textstr )

        return pphrase

    """
    Returns bitvector of cipher read by file
    """
    def readCipher(self, filename = "out.txt"):
        ENCRYPTED_HEX = open(filename, 'r').readlines()[0]
        cipher = BitVector(hexstring = ENCRYPTED_HEX)
        return cipher

    @staticmethod
    def is_space(ch):
        # returns true if ord(char) is 0
        return True if ord(ch) == 0x00 else False
    
    @staticmethod
    def is_ascii(ch):
        # returns true if ord(char) is in ascii
        return True if ch in string.ascii_letters else False
    
    @staticmethod
    def xor(s1, s2):
        # return xor of two bitvectors
        min_bvlen = min(len(s1), len(s2))
        return s1[:min_bvlen] ^ s2[:min_bvlen]


    def spaces_count(self, text):
        # count number of spaces in string
        counter = Counter()
        for index, char in enumerate(text):
            # if space or any printable char
            if self.is_space(char) or self.is_ascii(char):
                counter[index] += 1
        return counter

    """
    Removes the previous cipher blocks from each block
    """
    def removePrevCipherBlocks(self, cipher, totalCipherBlock):
        previous_cb = self.getPassPhrase()
        newCipher = BitVector(size = 0)
        for i in range(0, totalCipherBlock):
            current_cb = cipher[i*self.BLOCKSIZE: (i+1)*self.BLOCKSIZE]
            newCipher += current_cb^ previous_cb
            previous_cb = current_cb
        return newCipher


    @staticmethod
    def generateKeyVector(key):
        # Returns the Bitvector of list of decimal values
        keybv = BitVector(size = 0)
        for k in key:
            keybv += BitVector(intVal = k, size = 8)
        return keybv

    """
    Decrypts message from obtained key and mod. ciphertext
    """
    def decryptMsg(self, newCipher, keybv, totalCipherBlock):
        decryptedpt = BitVector(size = 0)
        for i in range(0, totalCipherBlock):
            msg =  newCipher[i*self.BLOCKSIZE: (i+1)*self.BLOCKSIZE] ^ keybv
            decryptedpt += msg
        return decryptedpt.get_bitvector_in_ascii()


    """
    Main FUnction that takes file name of cipher text,
    and return the plain text.
    Computes possible spaces in the text.
    """
    def attack(self, cfname):
        cipher = self.readCipher(cfname)
        totalCipherBlock = len(cipher) // self.BLOCKSIZE 
        newCipher = self.removePrevCipherBlocks(cipher, totalCipherBlock)
        
        key = [None for _ in range(self.numbytes)]
        
        for i1 in range(0, totalCipherBlock):
            counter = Counter()
            c1 = newCipher[i1*self.BLOCKSIZE: (i1+1)*self.BLOCKSIZE]
            for i2 in range(0, totalCipherBlock):
                c2 = newCipher[i2*self.BLOCKSIZE: (i2+1)*self.BLOCKSIZE]
                if i1 != i2:
                    xored = self.xor(c1, c2)
                    counter.update(
                        self.spaces_count(xored.get_bitvector_in_ascii())
                    )
                    
            for index, count in counter.items():
                if count > totalCipherBlock*self.THRESHOLD:
                    # pi ^ ci = key; pi = space
                    outer_c = c1.get_bitvector_in_ascii()
                    key[index] = self.SPACE_ASCII ^ ord(outer_c[index])

        keybv = self.generateKeyVector(key)
        return self.decryptMsg(newCipher, keybv, totalCipherBlock)



"""
Method 2: 
Oracle Padding Attack: If cipher text length is less than 180 characters, go for this method. 
"""
class CrackCBCOracleAttack(object):
    def __init__(self):
        self.BLOCKSIZE = 64
        self.numbytes = self.BLOCKSIZE // 8
    
    def getPassPhrase(self):
        PassPhrase = "I want to learn cryptograph and network security"
        # Reduce the passphrase to a bit array of size BLOCKSIZE:
        pphrase = BitVector(bitlist = [0]*self.BLOCKSIZE)
        for i in range(0,len(PassPhrase) // self.numbytes):
            textstr = PassPhrase[i*self.numbytes:(i+1)*self.numbytes]
            pphrase ^= BitVector( textstring = textstr )

        return pphrase

    def readCipher(self, filename = "ciphertext.txt"):
        ENCRYPTED_HEX = open(filename, 'r').readlines()[0]
        cipher = BitVector(hexstring = ENCRYPTED_HEX)
        return cipher

    def getKeybyPadding(self, cipher):
        ### Getting KEy from last block
        clen = len(cipher)
        previous_block =  cipher[
            clen - 2*self.BLOCKSIZE: 
            clen - self.BLOCKSIZE
        ]
        ct = cipher[clen - self.BLOCKSIZE: clen]
        ct ^= BitVector(intVal = 0, size = self.BLOCKSIZE)    # plain text
        ct ^= previous_block
        key = ct.deep_copy()
        return key


    def attack(self, fname):
        cipher = self.readCipher(fname)
        pphrase = self.getPassPhrase()
        key = self.getKeybyPadding(cipher)

        oldTotalChars = 0
        # key = BitVector(size = 8, intVal = 0) + keyx[8:]
        msg_encrypted_bv = BitVector( size = 0 )
        previous_block = pphrase
        for i in range(0, len(cipher) // self.BLOCKSIZE):
            ct = cipher[i*self.BLOCKSIZE: (i+1)*self.BLOCKSIZE]
            ct ^= key
            ct ^= previous_block
            previous_block = cipher[i*self.BLOCKSIZE: (i+1)*self.BLOCKSIZE]
            msg_encrypted_bv += ct

        return self.print_pt(msg_encrypted_bv, len(cipher))


    def print_pt(self, msg_encrypted_bv, cipher_len):
        obtain_pt = BitVector( size = 0 )
        NUMB_BLOCKS = cipher_len//self.numbytes//self.BLOCKSIZE
        spacesUpper = list()
        totalCharsFound = 0
        plainText = str()
        for i in range(0, cipher_len // 8):
            char = msg_encrypted_bv[i*8: (i+1)*8].getTextFromBitVector()
            obtain_pt += BitVector(textstring = char)
            if char in string.ascii_uppercase:
                spacesUpper.append(char)
            if char in string.printable and char in string.ascii_letters:
                plainText += char
                totalCharsFound += 1
            else:
                plainText += "_"
        return plainText




if __name__ == "__main__":
    # oracle_padding_attack()
    cfname = "ciphertext.txt"
    if sys.version_info[0] == 3:   
        cfname = input("\nEnter filname of cipher text to crack: ")
    else:                                                                         
        cfname = raw_input("\nEnter filname of cipher text to crack: ")
    


    BLOCKSIZE = 64
    NUMB_BLOCKS = 0
    with open(cfname, "r") as cfc:
        NUMB_BLOCKS = len(cfc.read())//(BLOCKSIZE//4)

    print(f"Number of cipher blocks is: {NUMB_BLOCKS} blocks.")
   
    if NUMB_BLOCKS < BLOCK_THRESHOLD:
        print("\nLength of cipher is small, so using Oracle Padding attack")
        c = CrackCBCOracleAttack()
        decrypted_msg = c.attack(cfname)
    else:
        print("Length of cipher is more than sufficient, so using Spacing MTP attack")
        c = CrackCBCBySpaceAttack()
        decrypted_msg = c.attack(cfname)


    print("Crack started!!")
    print("Please wait for crack to finish, this will take few seconds...")


    dmsg = str()
    for ch in decrypted_msg:
        if ch in string.ascii_letters or ch in string.printable:
            dmsg += ch
        else:
            dmsg += "_"

    with open("recoveredtext.txt", "w") as wb:
        wb.write(dmsg)
    print(f"\n\nPlain text is written into recoveredtext.txt file.")
    
 