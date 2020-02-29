#!/usr/bin/env python
# crack_classical.py

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
==> C'(i) = P(i) ^ K
==> P(i) = C'(i) ^ K 

Its in MTP, with each block is encrypted with same key.
We can use space attack, just as we used in other question.
"""

import sys
from BitVector import BitVector
import string


# can be changed to anything, only first block get affected
PassPhrase = "I want to learn cryptograph and network security"

"""
Method 1:
Space attack in MTP: If cipher text length is more than 180 characters, go for this method. 
"""
class crackCBC(object):
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

    """
    takes int key, and returns the bit vector object
    """
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
    Get the last block by xoring with its previous one
    Assuming last block is zero padded i.e., plain text
    find the key, with this assumption.
    """
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


    """
    Returns bitvector of cipher read by file
    """
    def readCipher(self, filename = "ciphertext.txt"):
        ENCRYPTED_HEX = open(filename, 'r').readlines()[0]
        cipher = BitVector(hexstring = ENCRYPTED_HEX)
        return cipher


    """
    Other Main Function that takes cipher text and returns key.
    It computes key, if there is zero padding available
    """
    def orcale_paddng_attack(self, cipher):
        oldTotalChars = 0
        # get passphrase bv
        pphrase = self.getPassPhrase()

        # get key from oracle padding attack
        key = self.getKeybyPadding(cipher)
        # assume 7  bytes of key and initial 0 byte
        key = BitVector(size = 8, intVal = 0) + key[8:]
        msg_encrypted_bv = BitVector( size = 0 )
        previous_block = pphrase
        for i in range(0, len(cipher) // self.BLOCKSIZE):
            ct = cipher[i*self.BLOCKSIZE: (i+1)*self.BLOCKSIZE]
            ct ^= key
            ct ^= previous_block
            previous_block = cipher[i*self.BLOCKSIZE: (i+1)*self.BLOCKSIZE]
            msg_encrypted_bv += ct

        return key


    """
    Main Function that takes file name of cipher text and key from orcale_paddng_attack,
    and return the plain text.
    Computes possible spaces in the text.
    """
    def spacing_mtp_attack(self, cipher, key):
        totalCipherBlock = len(cipher) // self.BLOCKSIZE 
        newCipher = self.removePrevCipherBlocks(cipher, totalCipherBlock)
        
        key = [ord(k) for k in key.get_bitvector_in_ascii()]
        
        for i1 in range(0, totalCipherBlock):
            spaceCounter = dict()
            c1 = newCipher[i1*self.BLOCKSIZE: (i1+1)*self.BLOCKSIZE]
            for i2 in range(0, totalCipherBlock):
                c2 = newCipher[i2*self.BLOCKSIZE: (i2+1)*self.BLOCKSIZE]
                if i1 != i2:
                    xored = self.xor(c1, c2)

                    for index, char in enumerate(xored.get_bitvector_in_ascii()):
                        # if space or any printable char
                        if self.is_space(char) or self.is_ascii(char):
                            if index not in spaceCounter.keys():
                                spaceCounter[index] = 1
                            else:
                                spaceCounter[index] += 1


            for index, count in spaceCounter.items():
                if count > totalCipherBlock*self.THRESHOLD:
                    # pi ^ ci = key; pi = space
                    outer_c = c1.get_bitvector_in_ascii()
                    key[index] = self.SPACE_ASCII ^ ord(outer_c[index])

        keybv = self.generateKeyVector(key)
        return self.decryptMsg(newCipher, keybv, totalCipherBlock)

    """
     Writes back the messages decrypted.
    """
    def writeDecryptedPlainText(self, decrypted_msg):
        with open("recoveredtext.txt", "w", newline = "") as wb:
            wb.write(decrypted_msg)


if __name__ == "__main__":
    cfname = "ciphertext.txt"
    if sys.version_info[0] == 3:   
        cfname = input("\nEnter filname of cipher text to crack: ")
    else:                                                                         
        cfname = raw_input("\nEnter filname of cipher text to crack: ")
    
    print("Crack started!!")
    print("Please wait for crack to finish, this will take few seconds...")

    try:
        c = crackCBC()
        cipher = c.readCipher(cfname)
        key = c.orcale_paddng_attack(cipher)
        decrypted_msg = c.spacing_mtp_attack(cipher, key).strip("\n \0\t")
        c.writeDecryptedPlainText(decrypted_msg)
    except Exception as e:
        print(f"Exception caught: {type(e).__name__}")
        
    print(f"\n\nPlain text is written into recoveredtext.txt file.\n")
    
 