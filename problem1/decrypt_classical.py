#!/usr/bin/env python
# decrypt_classical.py

__author__ = "Jai Singhal"
__copyright__ = "Copyright Feb, 2020"
__version__ = "1.0.0"
__maintainer__ = "Jai Singhal"
__email__ = "h20190021@pilani.bits-pilani.ac.in"
__website__ = "http://jai-singhal.github.io"
# __github_repo__ = "https://github.com/jai-singhal/encrypt-decrypt"

"""
###  Call syntax:
###  $ python3 decrypt.py  encrypt_txt.txt  out_plain.txt
###
###  Input will be key, default key= bits@f463
###  The decrypted output is deposited in the file `out_plain.txt'
"""

import sys
from BitVector import *

if len(sys.argv) is not 3:
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypt file and the other for the '''
             '''decrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"

BLOCKSIZE = 64
numbytes = BLOCKSIZE // 8

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )


# Get key from user:
key = None
if sys.version_info[0] == 3:
    key = input("\nEnter key: ")
else:
    key = raw_input("\nEnter key: ")
key = key.strip()


# Reduce the key to a bit array of size BLOCKSIZE:
key_bv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(key) // numbytes):
    keyblock = key[i*numbytes:(i+1)*numbytes]
    key_bv ^= BitVector( textstring = keyblock )


# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector(size = 0)

# Carry out differential XORing of bit blocks and encryption:
previous_block = bv_iv
ENCRYPTED_HEX = open(sys.argv[1], 'r').readlines()[0]
cipher = BitVector(hexstring = ENCRYPTED_HEX)

for i in range(0, len(cipher) // BLOCKSIZE):
    ct = cipher[i*BLOCKSIZE: (i+1)*BLOCKSIZE]
    ct ^= key_bv
    ct ^= previous_block
    previous_block = cipher[i*BLOCKSIZE: (i+1)*BLOCKSIZE]
    msg_encrypted_bv += ct

out = msg_encrypted_bv.getTextFromBitVector().strip(' \t\r\n\0')

# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], 'w', newline="")
FILEOUT.write(out)
FILEOUT.close()   