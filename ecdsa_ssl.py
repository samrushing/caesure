# -*- Mode: Python -*-

import ctypes
import ctypes.util

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl'))

# this specifies the curve used with ECDSA.
NID_secp256k1 = 714 # from openssl/obj_mac.h

class KEY:

    def __init__ (self):
        self.k = ssl.EC_KEY_new_by_curve_name (NID_secp256k1)

    # XXX destructor!

    def generate (self):
        return ssl.EC_KEY_generate_key (self.k)

    def set_privkey (self, key):
        self.mb = ctypes.create_string_buffer (key)
        self.kp = ctypes.c_void_p (self.k)
        print ssl.d2i_ECPrivateKey (ctypes.byref (self.kp), ctypes.byref (ctypes.pointer (self.mb)), len(key))

    def set_pubkey (self, key):
        self.mb = ctypes.create_string_buffer (key)
        self.kp = ctypes.c_void_p (self.k)
        print ssl.o2i_ECPublicKey (ctypes.byref (self.kp), ctypes.byref (ctypes.pointer (self.mb)), len(key))

    def get_privkey (self):
        size = ssl.i2d_ECPrivateKey (self.k, 0)
        mb_pri = ctypes.create_string_buffer (size)
        ssl.i2d_ECPrivateKey (self.k, ctypes.byref (ctypes.pointer (mb_pri)))
        return mb_pri.raw

    def get_pubkey (self):
        size = ssl.i2o_ECPublicKey (self.k, 0)
        mb = ctypes.create_string_buffer (size)
        ssl.i2o_ECPublicKey (self.k, ctypes.byref (ctypes.pointer (mb)))
        return mb.raw

    def sign (self, hash):
        sig_size = ssl.ECDSA_size (self.k)
        mb_sig = ctypes.create_string_buffer (sig_size)
        sig_size0 = ctypes.POINTER (ctypes.c_int)()
        assert 1 == ssl.ECDSA_sign (0, hash, len (hash), mb_sig, ctypes.byref (sig_size0), self.k)
        return mb_sig.raw

    def verify (self, hash, sig):
        return ssl.ECDSA_verify (0, hash, len(hash), sig, len(sig), self.k)
