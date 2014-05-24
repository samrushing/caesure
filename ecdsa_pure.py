# -*- Mode: Python -*-

# Note: The ecsa module now supports secp256k1 natively, so this module needs to be redone.

# If you can't (or don't want to) use the ctypes ssl code, this drop-in
#   replacement uses the pure-python ecdsa package.
#
# https://github.com/warner/python-ecdsa
# $ easy_install ecdsa
#

# Note: as of 2014.05, this ecdsa package does not yet support compressed keys.

# WORRY: are the random numbers from random.SystemRandom() good enough?

import ecdsa

class KEY:

    def __init__ (self):
        self.prikey = None
        self.pubkey = None

    def generate (self):
        self.prikey = ecdsa.SigningKey.generate (curve=ecdsa.SECP256k1)
        self.pubkey = self.prikey.get_verifying_key()
        return self.prikey.to_der()

    def set_privkey (self, key):
        self.prikey = ecdsa.SigningKey.from_der (key)

    def set_pubkey (self, key):
        key = key[1:]
        self.pubkey = ecdsa.VerifyingKey.from_string (key, curve=secp256k1)

    def get_privkey (self):
        return self.prikey.to_der()

    def get_pubkey (self):
        return self.pubkey.to_der()

    def sign (self, hash):
        sig = self.prikey.sign_digest (hash, sigencode=ecdsa.util.sigencode_der)
        return sig.to_der()

    def verify (self, hash, sig):
        return self.pubkey.verify_digest (sig[:-1], hash, sigdecode=ecdsa.util.sigdecode_der)
