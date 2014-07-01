# -*- Mode: Cython -*-

from libcpp.string cimport string

cdef extern:
    int _ecdsa_verify (
        string * pub,
        string * data,
        string * sig,
        )

def ecdsa_verify (bytes _pubkey, bytes _data, bytes _sig):
    cdef string pubkey = _pubkey
    cdef string data = _data
    cdef string sig = _sig
    return _ecdsa_verify (&pubkey, &data, &sig)
