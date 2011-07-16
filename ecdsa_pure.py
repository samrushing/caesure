# -*- Mode: Python -*-

# If you can't (or don't want to) use the ctypes ssl code, this drop-in
#   replacement uses the pure-python ecdsa package.  Note: it stores private keys
#   using an OID to indicate the curve, while openssl puts the curve parameters
#   in each key.  The ecdsa package doesn't understand that DER, though.  So if you
#   create a wallet using one version, you must continue to use that version.  In an
#   emergency you could write a converter.

#
# https://github.com/warner/python-ecdsa
# $ easy_install ecdsa
#

# curve parameters below were taken from: 
#  http://forum.bitcoin.org/index.php?topic=23241.msg292364#msg292364

# WORRY: are the random numbers from random.SystemRandom() good enough?

import ecdsa
import random

# secp256k1
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp (_p, _a, _b)
generator_secp256k1 = g = ecdsa.ellipticcurve.Point (curve_secp256k1, _Gx, _Gy, _r)
randrange = random.SystemRandom().randrange
secp256k1 = ecdsa.curves.Curve (
    "secp256k1",
    curve_secp256k1,
    generator_secp256k1,
    (1, 3, 132, 0, 10)
    )
# add this to the list of official NIST curves.
ecdsa.curves.curves.append (secp256k1)

class KEY:

    def __init__ (self):
        self.prikey = None
        self.pubkey = None

    def generate (self):
        self.prikey = ecdsa.SigningKey.generate (curve=secp256k1)
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
