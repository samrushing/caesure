# -*- Mode: Python -*-

import caesure.secp256k1
from bitcoin import dhash

class KEY:

    def __init__ (self):
        self.p = None

    def set_pubkey (self, key):
        self.p = key

    def verify (self, data, sig):
        return caesure.secp256k1.verify (self.p, dhash (data), sig)
