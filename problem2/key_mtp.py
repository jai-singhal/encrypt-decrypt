import os
import sys
import base64
from BitVector import BitVector
import time
import hmac
import hashlib
import secrets

def generateKey(keysize = 64):
	## TOTP: Time-Based One-Time Password Algorithm
    # refer https://tools.ietf.org/html/rfc6238
    secret = secrets.token_hex(keysize).encode()
    totp = base64.b64encode(str(time.time()).encode("ascii"))

    ## HOTP: An HMAC-Based One-Time Password Algorithm
    # refer https://tools.ietf.org/html/rfc4226
    hotp_mac_sha512 = hmac.new(key = secret, msg = totp, digestmod=hashlib.sha512).hexdigest()
    hotp = hotp_mac_sha512[:keysize]

    # convert to bitvector
    bv = BitVector(textstring = hotp)
    return bv


if __name__ == "__main__":
    key_size = None
    if sys.version_info[0] == 3:                                             
        key_size = input("\nEnter size of key: ")            
    else:                                                                         
        key_size = raw_input("\nEnter size of key: ")
    key_size = int(key_size.strip())

    key = generateKey(key_size)
    print(key)