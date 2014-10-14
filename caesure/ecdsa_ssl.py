# -*- Mode: Python -*-

from coro.ssl.openssl import ecdsa
from bitcoin import dhash

# this specifies the curve used with ECDSA.
NID_secp256k1 = 714  # from openssl/obj_mac.h

class KEY:

    def __init__ (self):
        self.k = ecdsa (NID_secp256k1)

    def set_pubkey (self, key):
        self.k.set_pubkey (key)

    def verify (self, data, sig):
        vhash = dhash (data)
        return self.k.verify (vhash, sig)
