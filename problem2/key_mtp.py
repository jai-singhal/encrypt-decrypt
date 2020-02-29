#!/usr/bin/env python
# key_mtp.py

__author__ = "Jai Singhal"
__copyright__ = "Copyright Feb, 2020"
__version__ = "1.0.0"
__maintainer__ = "Jai Singhal"
__email__ = "h20190021@pilani.bits-pilani.ac.in"
__website__ = "https://jai-singhal.github.io"
__github_repo__ = "https://github.com/jai-singhal/encrypt-decrypt"


import os
import sys
import base64
from BitVector import BitVector
import time
import hmac
import hashlib
import secrets

def generateKey(keysize = 64): # in bytes
	bv = BitVector(size = 0)

	for i in range(0, keysize//64 + 1):
		## TOTP: Time-Based One-Time Password Algorithm
		# refer https://tools.ietf.org/html/rfc6238
		secret = secrets.token_hex(512).encode()
		totp = base64.b64encode(str(time.time() + i).encode("ascii"))
		## HOTP: An HMAC-Based One-Time Password Algorithm
		# refer https://tools.ietf.org/html/rfc4226
		hotp = hmac.new(key = secret, msg = totp, digestmod=hashlib.sha512).hexdigest()
		# convert to bitvector
		bv += BitVector(hexstring = hotp)

	return bv[0:keysize*8]


if __name__ == "__main__":
	key_size = None
	if sys.version_info[0] == 3:                                             
		key_size = input("\nEnter size of key: ")            
	else:                                                                         
		key_size = raw_input("\nEnter size of key: ")
	key_size = int(key_size.strip())

	try:
		key = generateKey(key_size)
		print(key.get_bitvector_in_hex())
	except Exception as e:
		print(f"Exception caught: {type(e).__name__}")
