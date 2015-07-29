# -*- Mode: Cython; indent-tabs-mode: nil -*-

# https://github.com/bitcoin/secp256k1

cdef extern from "secp256k1.h":
    cdef enum:
        SECP256K1_CONTEXT_VERIFY = (1 << 0)
        SECP256K1_CONTEXT_SIGN   = (1 << 1)
    ctypedef struct secp256k1_context_t
    secp256k1_context_t * secp256k1_context_create (int flags)
    void secp256k1_context_destroy (secp256k1_context_t * ctx)
    int secp256k1_ecdsa_verify (
        const secp256k1_context_t* ctx,
        const unsigned char *msg32,
        const unsigned char *sig,
        int siglen,
        const unsigned char *pubkey,
        int pubkeylen
    )
    ctypedef int (*secp256k1_nonce_function_t) (
        unsigned char *nonce32,
        const unsigned char *msg32,
        const unsigned char *key32,
        unsigned int attempt,
        const void *data
    )
    extern const secp256k1_nonce_function_t secp256k1_nonce_function_rfc6979
    extern const secp256k1_nonce_function_t secp256k1_nonce_function_default
    int secp256k1_ecdsa_sign (
        const secp256k1_context_t* ctx,
        const unsigned char *msg32,
        unsigned char *sig,
        int *siglen,
        const unsigned char *seckey,
        secp256k1_nonce_function_t noncefp,
        const void *ndata
    )
    int secp256k1_ecdsa_sign_compact(
        const secp256k1_context_t* ctx,
        const unsigned char *msg32,
        unsigned char *sig64,
        const unsigned char *seckey,
        secp256k1_nonce_function_t noncefp,
        const void *ndata,
        int *recid
    )
    int secp256k1_ecdsa_recover_compact(
        const secp256k1_context_t* ctx,
        const unsigned char *msg32,
        const unsigned char *sig64,
        unsigned char *pubkey,
        int *pubkeylen,
        int compressed,
        int recid
    )
    int secp256k1_ec_seckey_verify(
        const secp256k1_context_t* ctx,
        const unsigned char *seckey
    )
    int secp256k1_ec_pubkey_verify(
        const secp256k1_context_t* ctx,
        const unsigned char *pubkey,
        int pubkeylen
    )
    int secp256k1_ec_pubkey_create(
        const secp256k1_context_t* ctx,
        unsigned char *pubkey,
        int *pubkeylen,
        const unsigned char *seckey,
        int compressed
    )
    int secp256k1_ec_pubkey_compress(
        const secp256k1_context_t* ctx,
        const unsigned char *pubkeyin,
        unsigned char *pubkeyout,
        int *pubkeylen
    )
    int secp256k1_ec_pubkey_decompress(
        const secp256k1_context_t* ctx,
        const unsigned char *pubkeyin,
        unsigned char *pubkeyout,
        int *pubkeylen
    )
    int secp256k1_ec_privkey_export(
        const secp256k1_context_t* ctx,
        const unsigned char *seckey,
        unsigned char *privkey,
        int *privkeylen,
        int compressed
    )
    int secp256k1_ec_privkey_import(
        const secp256k1_context_t* ctx,
        unsigned char *seckey,
        const unsigned char *privkey,
        int privkeylen
    )
    int secp256k1_ec_privkey_tweak_add(
        const secp256k1_context_t* ctx,
        unsigned char *seckey,
        const unsigned char *tweak
    )
    int secp256k1_ec_pubkey_tweak_add(
        const secp256k1_context_t* ctx,
        unsigned char *pubkey,
        int pubkeylen,
        const unsigned char *tweak
    )
    int secp256k1_ec_privkey_tweak_mul(
        const secp256k1_context_t* ctx,
        unsigned char *seckey,
        const unsigned char *tweak
    )
    int secp256k1_ec_pubkey_tweak_mul(
        const secp256k1_context_t* ctx,
        unsigned char *pubkey,
        int pubkeylen,
        const unsigned char *tweak
    )
    int secp256k1_context_randomize(
        secp256k1_context_t* ctx,
        const unsigned char *seed32
    )

class Error (Exception):
    pass
class ContextError (Error):
    pass
class IncorrectSignature (Error):
    pass
class InvalidPublicKey (Error):
    pass
class InvalidSignature (Error):
    pass
class BadNonce (Error):
    pass

cdef class Context:

    cdef secp256k1_context_t * ctx

    def __init__ (self, verify=True, sign=False):
        cdef unsigned int flags = 0
        if verify:
            flags |= SECP256K1_CONTEXT_VERIFY
        if sign:
            flags |= SECP256K1_CONTEXT_SIGN
        self.ctx = secp256k1_context_create (flags)
        if not self.ctx:
            raise ContextError

    def __del__ (self):
        if self.ctx:
            secp256k1_context_destroy (self.ctx)
        self.ctx = NULL

    def verify (self, bytes pubkey, bytes data, bytes sig):
        cdef int r
        assert len(data) == 32
        r = secp256k1_ecdsa_verify (self.ctx, data, sig, len(sig), pubkey, len(pubkey))
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

    def sign (self, bytes msg32, bytes skey, bytes nonce):
        cdef unsigned char sig[72]
        cdef int siglen = 72;
        cdef int r
        assert len(skey)  == 32
        assert len(msg32) == 32
        assert len(nonce) == 32
        r = secp256k1_ecdsa_sign (self.ctx, msg32, sig, &siglen, skey, NULL, NULL)
        if r == 0:
            raise Error
        else:
            return sig[:siglen]
