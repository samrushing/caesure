# -*- Mode: Python -*-

import caesure.secp256k1
from .secp256k1 import verify, start, Error as secp256k1_Error
from .bitcoin import dhash

caesure.secp256k1.start (verify=True, sign=False)

class KEY:

    def __init__ (self):
        self.p = None

    def set_pubkey (self, key):
        self.p = key

    def verify (self, data, sig, already):
        if not already:
            data = dhash (data)
        try:
            caesure.secp256k1.verify (self.p, data, sig)
            return 1
        except secp256k1_Error:
            return 0
    
