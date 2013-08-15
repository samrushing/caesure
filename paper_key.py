# -*- Mode: Python -*-

# standalone, self-contained paper wallet generator
import ctypes
import ctypes.util
import sys
import hashlib
from hashlib import sha256

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl'))

# this specifies the curve used with ECDSA.
NID_secp256k1 = 714 # from openssl/obj_mac.h

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result
ssl.EC_KEY_get0_private_key.restype = ctypes.c_void_p
ssl.EC_KEY_get0_private_key.errcheck = check_result
ssl.BN_bn2hex.restype = ctypes.c_char_p

class KEY:

    def __init__ (self):
        self.k = ssl.EC_KEY_new_by_curve_name (NID_secp256k1)

    def __del__ (self):
        ssl.EC_KEY_free (self.k)
        self.k = None

    def generate (self):
        return ssl.EC_KEY_generate_key (self.k)

    def get_privkey_bignum (self):
        pk = ssl.EC_KEY_get0_private_key (self.k)
        return ssl.BN_bn2hex (pk).decode ('hex')

    def get_pubkey_bignum (self):
        size = ssl.i2o_ECPublicKey (self.k, 0)
        if size == 0:
            raise SystemError
        else:
            mb = ctypes.create_string_buffer (size)
            ssl.i2o_ECPublicKey (self.k, ctypes.byref (ctypes.pointer (mb)))
            return mb.raw

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
    import sys
    if len(sys.argv) > 1:
        nkeys = int (sys.argv[1])
    else:
        nkeys = 1
    for i in range (nkeys):
        k = KEY()
        k.generate()
        pri = k.get_privkey_bignum()
        pub = k.get_pubkey_bignum()
        print 'private:', pkey_to_address (pri)
        print 'public:', key_to_address (rhash (pub))
        k = None

        
