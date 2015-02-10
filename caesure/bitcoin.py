# -*- Mode: Python; indent-tabs-mode: nil -*-

import hashlib
import struct
import sys
import time

from hashlib import sha256
from pprint import pprint as pp

import caesure.proto

from caesure.proto import base58_encode, base58_decode, hexify, Name
from caesure.script import verifying_machine, verifying_machine_p2sh, pprint_script, unrender_int
from caesure._script import parse_script, ScriptError

def P (msg):
    sys.stdout.write (msg)

W = sys.stderr.write

class NetworkConfig:

    BITCOIN_PORT = 8333
    MAGIC = '\xf9\xbe\xb4\xd9'
    genesis_block_hash = Name ('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'.decode ('hex')[::-1])

    def goto_testnet (self):
        self.BITCOIN_PORT = 18333
        self.MAGIC = '\x0b\x11\x09\x07'
        self.genesis_block_hash = Name ('000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'.decode ('hex')[::-1])

network = NetworkConfig()

ZERO_NAME = Name ('\x00' * 32)

OBJ_TX    = 1
OBJ_BLOCK = 2

MAX_BLOCK_SIZE = 1000000
COIN           = 100000000
MAX_MONEY      = 21000000 * COIN

NULL_OUTPOINT = (ZERO_NAME, 4294967295)


def dhash (s):
    return sha256(sha256(s).digest()).digest()

def rhash (s):
    h1 = hashlib.new ('ripemd160')
    h1.update (sha256(s).digest())
    return h1.digest()

def bcrepr (n):
    return '%d.%08d' % divmod (n, 100000000)

# https://en.bitcoin.it/wiki/Proper_Money_Handling_(JSON-RPC)
def float_to_btc (f):
    return long (round (f * 1e8))

class BadAddress (Exception):
    pass

def key_to_address (s, version=0):
    s = chr(version) + s
    checksum = dhash (s)[:4]
    encoded = base58_encode (
        int ((s + checksum).encode ('hex'), 16)
    )
    pad = 0
    for c in s:
        if c == '\x00':
            pad += 1
        else:
            break
    return ('1' * pad) + encoded

def address_to_key (s, version=0):
    s = ('%050x' % base58_decode (s)).decode ('hex')
    key, check0 = s[:-4], s[-4:]
    check1 = dhash (key)[:4]
    if key[0] != chr(version) or check0 != check1:
        raise BadAddress (s)
    return key[1:]

def compute_rewards (n):
    l = []
    r = 50 * 100000000
    for i in range (n):
        l.append (r)
        r /= 2
    return l

# 60 years' worth
reward_schedule = compute_rewards (15)

def compute_reward (height):
    return reward_schedule [height // 210000]

class timer:

    def __init__ (self):
        self.start = time.time()

    def end (self):
        return time.time() - self.start

# pull in one of the ECDSA key implementations.

try:
    from ecdsa_secp256k1 import KEY
except ImportError:
    from ecdsa_ssl import KEY
#from ecdsa_cryptopp import KEY

class TX (caesure.proto.TX):

    def __init__ (self):
        self.version = 1
        self.lock_time = 0

    def copy (self):
        tx0 = TX()
        tx0.version = self.version
        tx0.lock_time = self.lock_time
        tx0.inputs = self.inputs[:]
        tx0.outputs = self.outputs[:]
        return tx0

    def get_hash (self):
        return Name (dhash (self.render()))

    def dump (self, fout=sys.stdout):
        D = fout.write
        D ('hash: %s\n' % (hexify (dhash (self.render())),))
        D ('inputs: %d\n' % (len(self.inputs)))
        for i in range (len (self.inputs)):
            (outpoint, index), script, sequence = self.inputs[i]
            try:
                redeem = pprint_script (parse_script (script))
            except ScriptError:
                redeem = script.encode ('hex')
            D ('%3d %064x:%d %r %d\n' % (i, outpoint, index, redeem, sequence))
        D ('outputs: %d\n' % (len(self.outputs),))
        for i in range (len (self.outputs)):
            value, pk_script = self.outputs[i]
            pk_script = pprint_script (parse_script (pk_script))
            D ('%3d %s %r\n' % (i, bcrepr (value), pk_script))
        D ('lock_time: %s\n' % (self.lock_time,))

    def render (self):
        return self.pack()

    def verify (self, index, lock_script, block_timestamp):
        outpoint, unlock_script, sequence = self.inputs[index]
        if block_timestamp >= 1333238400:
            m = verifying_machine_p2sh (self, index, KEY)
        else:
            m = verifying_machine (self, index, KEY)
        m.eval_script (unlock_script, lock_script)

class BadBlock (Exception):
    pass

class BLOCK (caesure.proto.BLOCK):

    def dump (self, fout=sys.stdout):
        fout.write (
            'version:%d\n'
            'prev_block:%r\n'
            'merkle_root:%r\n'
            'timestamp:%s\n'
            'bits:%08x\n'
            'nonce:%d\n' % (
                self.version,
                self.prev_block,
                self.merkle_root,
                self.timestamp,
                self.bits,
                self.nonce
            )
        )
        for i in range (len (self.transactions)):
            fout.write ('tx %d {\n' % (i,))
            self.transactions[i].dump (fout)
            fout.write ('}\n')

    def __len__ (self):
        return len (self.transactions)

    def get_height (self):
        if self.version < 2:
            raise ValueError ("no block height in version 1 blocks")
        else:
            tx0 = self.transactions[0]
            coinbase = tx0.inputs[0]
            ((outpoint_hash, outpoint_index), script, sequence) = coinbase
            # Note: we can't use parse_script here because coinbases are *not*
            #  guaranteed to be proper scripts.  At least yet.
            nbytes = ord(script[0])
            height = unrender_int (script[1:1 + nbytes])
            return height

    def make_TX (self):
        return TX()

    def check_bits (self):
        shift  = self.bits >> 24
        target = (self.bits & 0xffffff) * (1 << (8 * (shift - 3)))
        val = int (self.name)
        return val < target

    def get_merkle_hash (self):
        hl = [dhash (t.raw) for t in self.transactions]
        while 1:
            if len(hl) == 1:
                return Name (hl[0])
            if len(hl) % 2 != 0:
                hl.append (hl[-1])
            hl0 = []
            for i in range (0, len (hl), 2):
                hl0.append (dhash (hl[i] + hl[i + 1]))
            hl = hl0

    # see https://en.bitcoin.it/wiki/Protocol_rules
    def check_rules (self):
        if not len(self.transactions):
            raise BadBlock ("zero transactions")
        elif not self.check_bits():
            raise BadBlock ("did not achieve target")
        elif (time.time() - self.timestamp) < (-60 * 60 * 2):
            raise BadBlock ("block from the future")
        else:
            for i in range (len (self.transactions)):
                tx = self.transactions[i]
                if i == 0 and (len (tx.inputs) != 1 or tx.inputs[0][0] != NULL_OUTPOINT):
                    raise BadBlock ("first transaction not a generation")
                # XXX check block reward
                elif i == 0 and not (2 <= len (tx.inputs[0][1]) <= 100):
                    raise BadBlock ("bad sig_script in generation transaction")
                elif i > 0:
                    for outpoint, sig_script, sequence in tx.inputs:
                        if outpoint == NULL_OUTPOINT:
                            raise BadBlock ("transaction other than the first is a generation")
                for value, _ in tx.outputs:
                    if value > MAX_MONEY:
                        raise BadBlock ("too much money")
                    # XXX not checking SIGOP counts since we don't really implement the script engine.
            # check merkle hash
            if self.merkle_root != self.get_merkle_hash():
                raise BadBlock ("merkle hash doesn't match")
        # XXX more to come...

