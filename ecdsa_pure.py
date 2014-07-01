# -*- Mode: Python -*-

# If you can't (or don't want to) use the ctypes ssl code, this drop-in
#   replacement uses the pure-python ecdsa package.
#
# https://github.com/warner/python-ecdsa
# $ easy_install ecdsa
#

# Note: as of 2014.05, this ecdsa package does not yet support compressed keys.

import ecdsa
from bitcoin import dhash

class KEY:

    def __init__ (self):
        self.p = None

    def set_pubkey (self, key):
        self.pubkey = ecdsa.VerifyingKey.from_string (
            key[1:],
            curve=ecdsa.SECP256k1
        )

    def verify (self, to_hash, sig):
        return self.pubkey.verify_digest (
            sig,
            dhash (to_hash),
            sigdecode=ecdsa.util.sigdecode_der
        )
