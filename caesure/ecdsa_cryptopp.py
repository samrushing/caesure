# -*- Mode: Python -*-

import caesure.cryptopp
import hashlib

from coro.asn1.ber import *

# crypto++ requires a public key to be asn1 encoded in such a way that the
#   curve is also specified.

# this *might* be rfc5480

secp256k1 = SEQUENCE (
    INTEGER (1),
    SEQUENCE (
        OBJID ([1, 2, 840, 10045, 1, 1]),
    INTEGER (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fL),
    ),
    SEQUENCE (OCTET_STRING ('\x00'*32), OCTET_STRING (('\x00' * 31) + '\x07')),
    OCTET_STRING (
        '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179'
        '8483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode ('hex')
    ),
    INTEGER (0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141L),
    INTEGER (1),
)

ecdsa_oid = OBJID ([1, 2, 840, 10045, 2, 1])

# convert to the DER that crypto++ wants.
def pubkey_to_cryptopp (pub):
    return SEQUENCE (
        SEQUENCE (ecdsa_oid, secp256k1,),
        BITSTRING (0, pub),
        )

def der_to_sig (der):
    data, size = decode (der)
    [r, s] = data
    return ('%064x%064x' % (r, s)).decode ('hex')

class KEY:

    def __init__ (self):
        self.p = None

    def set_pubkey (self, key):
        # probably need to translate asn1
        self.p = pubkey_to_cryptopp (key)

    def verify (self, data, sig, already):
        # crypto++ ECDSA<ECP, SHA256>::PublicKey hashes *once*, we need *twice*.
        if not already:
            raise NotImplementedError ("crypto++ cannot verify pre-hashed data")
        h = hashlib.new ('sha256')
        h.update (data)
        d = h.digest()
        return caesure.cryptopp.ecdsa_verify (self.p, d, der_to_sig (sig))
