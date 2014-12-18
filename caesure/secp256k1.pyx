# -*- Mode: Cython; indent-tabs-mode: nil -*-

# https://github.com/bitcoin/secp256k1

cdef extern from "secp256k1.h":
    cdef enum:
        SECP256K1_START_VERIFY
        SECP256K1_START_SIGN
    void secp256k1_start (unsigned int flags)
    #  Verify an ECDSA signature.
    #  Returns: 1: correct signature
    #           0: incorrect signature
    #          -1: invalid public key
    #          -2: invalid signature
    # In:       msg32:     the 32-byte message hash being verified (cannot be NULL)
    #           sig:       the signature being verified (cannot be NULL)
    #           siglen:    the length of the signature
    #           pubkey:    the public key to verify with (cannot be NULL)
    #           pubkeylen: the length of pubkey
    # Requires starting using SECP256K1_START_VERIFY.
    #
    int secp256k1_ecdsa_verify (
        const unsigned char *msg32,
        const unsigned char *sig, int siglen,
        const unsigned char *pubkey, int pubkeylen
    )
    #    Create an ECDSA signature.
    #    Returns: 1: signature created
    #             0: nonce invalid, try another one
    #    In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
    #             seckey: pointer to a 32-byte secret key (cannot be NULL, assumed to be valid)
    #             nonce:  pointer to a 32-byte nonce (cannot be NULL, generated with a cryptographic PRNG)
    #    Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
    #    In/Out:  siglen: pointer to an int with the length of sig, which will be updated
    #                     to contain the actual signature length (<=72).
    #  Requires starting using SECP256K1_START_SIGN.
    #  
    int secp256k1_ecdsa_sign (
        const unsigned char *msg32,
        unsigned char *sig,
        int *siglen,
        const unsigned char *seckey,
        const unsigned char *nonce
    )

class Error (Exception):
    pass
class IncorrectSignature (Error):
    pass
class InvalidPublicKey (Error):
    pass
class InvalidSignature (Error):
    pass

def start (verify=True, sign=False):
    cdef unsigned int flags = 0
    if verify:
        flags |= SECP256K1_START_VERIFY
    if sign:
        flags |= SECP256K1_START_SIGN
    secp256k1_start (flags)

def verify (bytes pubkey, bytes data, bytes sig):
    cdef int r
    assert len(data) == 32
    r = secp256k1_ecdsa_verify (data, sig, len(sig), pubkey, len(pubkey))
    if r == 1:
        pass
    elif r == 0:
        raise IncorrectSignature (sig)
    elif r == -1:
        raise InvalidPublicKey (pubkey)
    elif r == -2:
        raise InvalidSignature (sig)
    else:
        raise Error

class BadNonce (Exception):
    pass

def sign (bytes msg32, bytes skey, bytes nonce):
    cdef unsigned char sig[72]
    cdef int siglen = 72;
    cdef int r
    assert len(skey)  == 32
    assert len(msg32) == 32
    assert len(nonce) == 32
    r = secp256k1_ecdsa_sign (msg32, sig, &siglen, skey, nonce)
    if r == 0:
        raise BadNonce (nonce)
    else:
        return sig[:siglen]
