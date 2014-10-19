# -*- Mode: Cython; indent-tabs-mode: nil -*-

# https://github.com/bitcoin/secp256k1

cdef extern from "secp256k1.h":
    int secp256k1_ecdsa_verify (
        const unsigned char *msg, int msglen,
        const unsigned char *sig, int siglen,
        const unsigned char *pubkey, int pubkeylen
    )
    void secp256k1_start()

secp256k1_start()

def verify (bytes pubkey, bytes data, bytes sig):
    return secp256k1_ecdsa_verify (
        data, len(data),
        sig, len(sig),
        pubkey, len(pubkey)
    )
