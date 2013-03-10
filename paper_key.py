# -*- Mode: Python -*-

# standalone paper wallet generator
import sys

import hashlib
from hashlib import sha256

# either of these will work
from ecdsa_ssl import KEY
#from ecdsa_pure import KEY

try:
    from zcoro.asn1.ber import decode
    def get_keys (der):
        d = decode (der)
        pri = d[0][1]
        pub = d[0][3][2][0][1][1]
        return pri, pub
except ImportError:
    from pyasn1.codec.ber.decoder import decode
    def unbin (bits):
        r = []
        for i in range (0, len (bits), 8):
            r.append (chr (int (''.join ([str(x) for x in bits[i:i+8]]), 2)))
        return ''.join (r)
    def get_keys (der):
        d = decode (der)
        pri = bytes (d[0][1])
        pub = unbin (d[0][3]._value)
        return pri, pub

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode (n):
    l = []
    while n > 0:
        n, r = divmod (n, 58)
        l.insert (0, (b58_digits[r]))
    return ''.join (l)

def base58_decode (s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index (ch)
        n += digit
    return n

def dhash (s):
    return sha256(sha256(s).digest()).digest()

def rhash (s):
    h1 = hashlib.new ('ripemd160')
    h1.update (sha256(s).digest())
    return h1.digest()

def key_to_address (s):
    checksum = dhash ('\x00' + s)[:4]
    return '1' + base58_encode (
        int ('0x' + (s + checksum).encode ('hex'), 16)
        )

def pkey_to_address (s):
    s = '\x80' + s
    checksum = dhash (s)[:4]
    return base58_encode (
        int ((s + checksum).encode ('hex'), 16)
        )
        
if __name__ == '__main__':
    k = KEY()
    k.generate()
    pri, pub = get_keys (k.get_privkey())
    print 'private:', pkey_to_address (pri)
    print 'public:', key_to_address (rhash (pub))
    
