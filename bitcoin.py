# -*- Mode: Python -*-

# A prototype bitcoin implementation.
#
# Author: Sam Rushing. http://www.nightmare.com/~rushing/
# July 2011 - Mar 2013
#
# Status: much of the protocol is done.  The crypto bits are now
#   working, and I can verify 'standard' address-to-address transactions.
#   There's a simple wallet implementation, which can now transact BTC.
# Todo: consider implementing the scripting engine.
# Todo: actually participate in the p2p network rather than being a lurker.
#

# blocks come in, they may or may not make it into the chain.  you can think
#   of them as having a 'provisional' block number.  i.e., if you can chain
#   them in somewhere, they have a block number. But it may not be the eventual
#   official block #n, because they may lose the race.
#
# thus num->block is 1->N and block->num is 1->1
#

import copy
import hashlib
import random
import struct
import socket
import time
import os
import pickle
import string
import sys

import coro
import coro.read_stream

from hashlib import sha256
from pprint import pprint as pp

import caesure.proto

W = coro.write_stderr

# these are overriden for testnet
BITCOIN_PORT = 8333
BITCOIN_MAGIC = '\xf9\xbe\xb4\xd9'
BLOCKS_PATH = 'blocks.bin'
genesis_block_hash = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

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

def bcrepr (n):
    return '%d.%08d' % divmod (n, 100000000)

# https://en.bitcoin.it/wiki/Proper_Money_Handling_(JSON-RPC)
def float_to_btc (f):
    return long (round (f * 1e8))

class BadAddress (Exception):
    pass

def key_to_address (s):
    checksum = dhash ('\x00' + s)[:4]
    return '1' + base58_encode (
        int ('0x' + (s + checksum).encode ('hex'), 16)
        )

def address_to_key (s):
    # strip off leading '1'
    s = ('%048x' % base58_decode (s[1:])).decode ('hex')
    hash160, check0 = s[:-4], s[-4:]
    check1 = dhash ('\x00' + hash160)[:4]
    if check0 != check1:
        raise BadAddress (s)
    return hash160

def pkey_to_address (s):
    s = '\x80' + s
    checksum = dhash (s)[:4]
    return base58_encode (
        int ((s + checksum).encode ('hex'), 16)
        )

# for some reason many hashes are reversed, dunno why.  [this may just be block explorer?]
def hexify (s, flip=False):
    if flip:
        return s[::-1].encode ('hex')
    else:
        return s.encode ('hex')

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex')[::-1]
    else:
        return s.decode ('hex')

def frob_hash (s):
    r = []
    for i in range (0, len (s), 2):
        r.append (s[i:i+2])
    r.reverse()
    return ''.join (r)

class timer:
    def __init__ (self):
        self.start = time.time()
    def end (self):
        return time.time() - self.start

# wallet file format: (<8 bytes of size> <private-key>)+
class wallet:

    # self.keys  : public_key -> private_key
    # self.addrs : addr -> public_key
    # self.value : addr -> { outpoint : value, ... }

    def __init__ (self, path):
        self.path = path
        self.keys = {}
        self.addrs = {}
        self.outpoints = {}
        # these will load from the cache
        self.last_block = 0
        self.total_btc = 0
        self.value = {}
        #
        try:
            file = open (path, 'rb')
        except IOError:
            file = open (path, 'wb')
            file.close()
            file = open (path, 'rb')
        while 1:
            size = file.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
                key = file.read (size)
                public_key = key[-65:] # XXX
                self.keys[public_key] = key
                pub0 = rhash (public_key)
                addr = key_to_address (pub0)
                self.addrs[addr] = public_key
                self.value[addr] = {} # overriden by cache if present
        # try to load value from the cache.
        self.load_value_cache()

    def load_value_cache (self):
        db = the_block_db
        cache_path = self.path + '.cache'
        try:
            file = open (cache_path, 'rb')
        except IOError:
            pass
        else:
            self.last_block, self.total_btc, self.value = pickle.load (file)
            file.close()
        db_last = db.last_block
        if not len(self.keys):
            print 'no keys in wallet'
            self.last_block = db_last
            self.write_value_cache()
        elif db_last < self.last_block:
            print 'the wallet is ahead of the block chain.  Disabling wallet for now.'
            global the_wallet
            the_wallet = None
        elif self.last_block < db_last:
            print 'scanning %d blocks from %d-%d' % (db_last - self.last_block, self.last_block, db_last)
            self.scan_block_chain (self.last_block)
            self.last_block = db_last
            # update the cache
            self.write_value_cache()
        else:
            print 'wallet cache is caught up with the block chain'
        # update the outpoint map
        for addr, outpoints in self.value.iteritems():
            for outpoint, value in outpoints.iteritems():
                self.outpoints[outpoint] = value
        print 'total btc in wallet:', bcrepr (self.total_btc)

    def write_value_cache (self):
        cache_path = self.path + '.cache'
        file = open (cache_path, 'wb')
        self.last_block = the_block_db.last_block
        pickle.dump ((self.last_block, self.total_btc, self.value), file)
        file.close()

    def new_key (self):
        k = KEY()
        k.generate()
        key = k.get_privkey()
        size = struct.pack ('<Q', len(key))
        file = open (self.path, 'ab')
        file.write (size)
        file.write (key)
        file.close()
        pubkey = k.get_pubkey()
        addr = key_to_address (rhash (pubkey))
        self.addrs[addr] = pubkey
        self.keys[pubkey] = key
        self.value[addr] = {}
        self.write_value_cache()
        return addr

    def check_tx (self, tx):
        dirty = False
        # did we send money somewhere?
        for outpoint, iscript, sequence in tx.inputs:
            if outpoint == NULL_OUTPOINT:
                # we don't generate coins
                continue
            sig, pubkey = parse_iscript (iscript)
            if sig and pubkey:
                addr = key_to_address (rhash (pubkey))
                if self.addrs.has_key (addr):
                    if not self.value[addr].has_key (outpoint):
                        raise KeyError ("input for send tx missing?")
                    else:
                        value = self.value[addr][outpoint]
                        self.value[addr][outpoint] = 0
                        self.outpoints[outpoint] = 0
                        self.total_btc -= value
                        dirty = True
                    print 'SEND: %s %s' % (bcrepr (value), addr,)
                    #import pdb; pdb.set_trace()
        # did we receive any moneys?
        i = 0
        rtotal = 0
        index = 0
        for value, oscript in tx.outputs:
            kind, addr = parse_oscript (oscript)
            if kind == 'address' and self.addrs.has_key (addr):
                hash = tx.get_hash()
                outpoint = hash, index
                if self.value[addr].has_key (outpoint):
                    raise KeyError ("outpoint already present?")
                else:
                    self.value[addr][outpoint] = value
                    self.outpoints[outpoint] += value
                    self.total_btc += value
                    dirty = True
                print 'RECV: %s %s' % (bcrepr (value), addr)
                rtotal += 1
            index += 1
            i += 1
        if dirty:
            self.write_value_cache()
        return rtotal

    def dump_value (self):
        addrs = self.value.keys()
        addrs.sort()
        sum = 0
        for addr in addrs:
            if len(self.value[addr]):
                print 'addr: %s' % (addr,)
                for (outpoint, index), value in self.value[addr].iteritems():
                    print '  %s %s:%d' % (bcrepr (value), outpoint.encode ('hex'), index)
                    sum += value
        print 'total: %s' % (bcrepr(sum),)

    def scan_block_chain (self, start):
        # scan the whole chain for any TX related to this wallet
        db = the_block_db
        blocks = db.num_block.keys()
        blocks.sort()
        total = 0
        for num in blocks:
            if num >= start:
                names = db.num_block[num]
                for name in names:
                    b = db[name]
                    for tx in b.transactions:
                        try:
                            n = self.check_tx (tx)
                            if len(names) > 1:
                                print 'warning: competing blocks involved in transaction!'
                            total += n
                        except:
                            print '*** bad tx'
                            tx.dump()
        print 'found %d txs' % (total,)

    def new_block (self, block):
        # only scan blocks if we have keys
        if len (self.addrs):
            for tx in block.transactions:
                self.check_tx (tx)

    def __getitem__ (self, addr):
        pubkey = self.addrs[addr]
        key = self.keys[pubkey]
        k = KEY()
        k.set_privkey (key)
        return k
    
    def build_send_request (self, value, dest_addr, fee=0):
        # first, make sure we have enough money.
        total = value + fee
        if total > self.total_btc:
            raise ValueError ("not enough funds")
        elif value <= 0:
            raise ValueError ("zero or negative value?")
        elif value < 1000000 and fee < 50000:
            # any output less than one cent needs a fee.
            raise ValueError ("fee too low")
        else:
            # now, assemble the total
            sum = 0
            inputs = []
            for addr, outpoints in self.value.iteritems():
                for outpoint, v0 in outpoints.iteritems():
                    if v0:
                        sum += v0
                        inputs.append ((outpoint, v0, addr))
                        if sum >= total:
                            break
                if sum >= total:
                    break
            # assemble the outputs
            outputs = [(value, dest_addr)]
            if sum > total:
                # we need a place to dump the change
                change_addr = self.get_change_addr()
                outputs.append ((sum - total, change_addr))
            inputs0 = []
            keys = []
            for outpoint, v0, addr in inputs:
                pubkey = self.addrs[addr]
                keys.append (self[addr])
                iscript = make_iscript ('bogus-sig', pubkey)
                inputs0.append ((outpoint, iscript, 4294967295))
            outputs0 = []
            for val0, addr0 in outputs:
                outputs0.append ((val0, make_oscript (addr0)))
            lock_time = 0
            tx = TX (inputs0, outputs0, lock_time)
            for i in range (len (inputs0)):
                tx.sign (keys[i], i)
            return tx

    def get_change_addr (self):
        # look for an empty key
        for addr, outpoints in self.value.iteritems():
            empty = True
            for outpoint, v0 in outpoints.iteritems():
                if v0 != 0:
                    empty = False
                    break
            if empty:
                # found one
                return addr
        return self.new_key()

# --------------------------------------------------------------------------------
#        ECDSA
# --------------------------------------------------------------------------------

# pull in one of the ECDSA key implementations.

from ecdsa_ssl import KEY
#from ecdsa_pure import KEY

# --------------------------------------------------------------------------------

OBJ_TX    = 1
OBJ_BLOCK = 2

object_types = {
    0: "ERROR",
    1: "TX",
    2: "BLOCK"
    }

MAX_BLOCK_SIZE = 1000000
COIN = 100000000
MAX_MONEY = 21000000 * COIN

# used to keep track of the parsing position when cracking packets
class position:
    def __init__ (self, val=0):
        self.origin = val
        self.val = val
    def __int__ (self):
        return self.val
    def __index__ (self):
        return self.val
    def incr (self, delta):
        self.val += delta
        if self.val - self.origin > MAX_BLOCK_SIZE:
            raise ValueError ("data > MAX_BLOCK_SIZE")
    def __repr__ (self):
        return '<pos %d>' % (self.val,)

# like struct.unpack_from, but it updates <position> as it reads
def unpack_pos (format, data, pos):
    result = struct.unpack_from (format, data, pos)
    pos.incr (struct.calcsize (format))
    return result

def unpack_var_int (d, pos):
    n0, = unpack_pos ('<B', d, pos)
    if n0 < 0xfd:
        return n0
    elif n0 == 0xfd:
        n1, = unpack_pos ('<H', d, pos)
        return n1
    elif n0 == 0xfe:
        n2, = unpack_pos ('<I', d, pos)
        return n2
    elif n0 == 0xff:
        n3, = unpack_pos ('<Q', d, pos)
        return n3

def unpack_var_str (d, pos):
    n = unpack_var_int (d, pos)
    result = d[pos.val:pos.val+n]
    pos.incr (n)
    return result

def unpack_net_addr (data, pos):
    services, addr, port = unpack_pos ('<Q16s2s', data, pos)
    addr = read_ip_addr (addr)
    # done separately because it's in network byte order
    port, = struct.unpack ('>H', port) # pos adjusted above
    return services, (addr, port)

def pack_net_addr ((services, (addr, port))):
    addr = pack_ip_addr (addr)
    port = struct.pack ('!H', port)
    return struct.pack ('<Q', services) + addr + port

def make_nonce():
    return random.randint (0, 1<<64L)

NULL_OUTPOINT = ('\x00' * 32, 4294967295)

class TX (caesure.proto.TX):

    ## def __init__ (self, inputs, outputs, lock_time, raw=None):
    ##     self.inputs = inputs
    ##     self.outputs = outputs
    ##     self.lock_time = lock_time
    ##     self.raw = raw

    def copy (self):
        return copy.deepcopy (self)

    def get_hash (self):
        return dhash (self.render())

    def dump (self):
        print 'hash: %s' % (hexify (dhash (self.render())),)
        print 'inputs: %d' % (len(self.inputs))
        for i in range (len (self.inputs)):
            (outpoint, index), script, sequence = self.inputs[i]
            print '%3d %s:%d %s %d' % (i, hexify(outpoint), index, hexify (script), sequence)
        print '%d outputs' % (len(self.outputs))
        for i in range (len (self.outputs)):
            value, pk_script = self.outputs[i]
            kind, addr = parse_oscript (pk_script)
            if not addr:
                addr = hexify (pk_script)
            print '%3d %s %s %r' % (i, bcrepr (value), kind, addr)
        print 'lock_time:', self.lock_time

    def render (self):
        version = 1
        result = [struct.pack ('<I', version)]
        result.append (pack_var_int (len (self.inputs)))
        for (outpoint, index), script, sequence in self.inputs:
            result.extend ([
                    struct.pack ('<32sI', outpoint, index),
                    pack_var_int (len (script)),
                    script,
                    struct.pack ('<I', sequence),
                    ])
        result.append (pack_var_int (len (self.outputs)))
        for value, pk_script in self.outputs:
            result.extend ([
                    struct.pack ('<Q', value),
                    pack_var_int (len (pk_script)),
                    pk_script,
                    ])
        result.append (struct.pack ('<I', self.lock_time))
        return ''.join (result)

    # Hugely Helpful: http://forum.bitcoin.org/index.php?topic=2957.20
    # NOTE: this currently verifies only 'standard' address transactions.
    def get_ecdsa_hash (self, index):
        tx0 = self.copy()
        iscript = tx0.inputs[index][1]
        # build a new version of the input script as an output script
        sig, pubkey = parse_iscript (iscript)
        pubkey_hash = rhash (pubkey)
        new_script = chr(118) + chr (169) + chr (len (pubkey_hash)) + pubkey_hash + chr (136) + chr (172)
        for i in range (len (tx0.inputs)):
            outpoint, script, sequence = tx0.inputs[i]
            if i == index:
                script = new_script
            else:
                script = ''
            tx0.inputs[i] = outpoint, script, sequence
        to_hash = tx0.render() + struct.pack ('<I', 1)
        return dhash (to_hash), sig, pubkey

    def sign (self, key, index):
        hash, _, pubkey = self.get_ecdsa_hash (index)
        assert (key.get_pubkey() == pubkey)
        # tack on the hash type byte.
        sig = key.sign (hash) + '\x01'
        iscript = make_iscript (sig, pubkey)
        op0, _, seq = self.inputs[index]
        self.inputs[index] = op0, iscript, seq
        return sig

    def verify (self, index):
        outpoint, script, sequence = self.inputs[index]
        if outpoint == NULL_OUTPOINT:
            # generation is considered verified - I assume by virtue of its hash value?
            return 1
        else:
            hash, sig, pubkey = self.get_ecdsa_hash (index)
            k = KEY()
            k.set_pubkey (pubkey)
            return k.verify (hash, sig)

def unpack_tx (data, pos):
    # has its own version number
    pos0 = pos.val
    version, = unpack_pos ('<I', data, pos)
    # mar 2013: I can find NO DOCUMENTATION on the upgrade to version 2 TX packets,
    #   i've scanned through all the damned BIPS one by one.  Boy it'd be nice if the
    #   protocol docs were kept up to date?  BIP34 mentions version 2 *blocks*, but not
    #   transactions...
    #if version != 1:
    #    raise ValueError ("unknown tx version: %d" % (version,))
    txin_count = unpack_var_int (data, pos)
    inputs = []
    outputs = []
    for i in range (txin_count):
        outpoint = unpack_pos ('<32sI', data, pos)
        script_length = unpack_var_int (data, pos)
        script = data[pos.val:pos.val+script_length]
        pos.incr (script_length)
        sequence, = unpack_pos ('<I', data, pos)
        inputs.append ((outpoint, script, sequence))
    txout_count = unpack_var_int (data, pos)
    for i in range (txout_count):
        value, = unpack_pos ('<Q', data, pos)
        pk_script_length = unpack_var_int (data, pos)
        pk_script = data[pos.val:pos.val+pk_script_length]
        pos.incr (pk_script_length)
        outputs.append ((value, pk_script))
    lock_time, = unpack_pos ('<I', data, pos)
    pos1 = pos.val
    return TX (inputs, outputs, lock_time, data[pos0:pos1])

# both generation and address push two values, so this is good for most things.

# The two numbers pushed by the input script for generation are
# *usually* a compact representation of the current target, and the
# 'extraNonce'.  But there doesn't seem to be any requirement for that;
# the eligius pool uses the string 'Elegius'.

def parse_iscript (s):
    # these tend to be push, push
    s0 = ord (s[0])
    if s0 > 0 and s0 < 76:
        # specifies the size of the first key
        k0 = s[1:1+s0]
        if len(s) == 1+s0:
            return k0, None
        else:
            s1 = ord (s[1+s0])
            if s1 > 0 and s1 < 76:
                k1 = s[2+s0:2+s0+s1]
                return k0, k1
            else:
                return None, None
    else:
        return None, None

def make_iscript (sig, pubkey):
    # XXX assert length limits
    sl = len (sig)
    kl = len (pubkey)
    return chr(sl) + sig + chr(kl) + pubkey

def parse_oscript (s):
    if (ord(s[0]) == 118 and ord(s[1]) == 169 and ord(s[-2]) == 136 and ord(s[-1]) == 172):
        # standard address output: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        size = ord(s[2])
        addr = key_to_address (s[3:size+3])
        assert (size+5 == len(s))
        return 'address', addr
    elif ord(s[0]) == (len(s) - 2) and ord (s[-1]) == 0xac:
        # generation: <pubkey>, OP_CHECKSIG
        return 'pubkey', s[1:-1]
    else:
        return 'unknown', s

def make_oscript (addr):
    # standard tx oscript
    key_hash = address_to_key (addr)
    return chr(118) + chr(169) + chr(len(key_hash)) + key_hash + chr(136) + chr(172)

def read_ip_addr (s):
    r = socket.inet_ntop (socket.AF_INET6, s)
    if r.startswith ('::ffff:'):
        return r[7:]
    else:
        return r

def pack_ip_addr (addr):
    # only v4 right now
    return socket.inet_pton (socket.AF_INET6, '::ffff:%s' % (addr,))

def pack_var_int (n):
    if n < 0xfd:
        return chr(n)
    elif n < 1<<16:
        return '\xfd' + struct.pack ('<H', n)
    elif n < 1<<32:
        return '\xfe' + struct.pack ('<I', n)
    else:
        return '\xff' + struct.pack ('<Q', n)

def pack_var_str (s):
    return pack_var_int (len (s)) + s

def pack_inv (pairs):
    result = [pack_var_int (len(pairs))]
    for objid, hash in pairs:
        result.append (struct.pack ('<I32s', objid, hash))
    return ''.join (result)

class BadBlock (Exception):
    pass

class BLOCK (caesure.proto.BLOCK):

    ## def __init__ (self, version, prev_block, merkle_root, timestamp, bits, nonce, transactions, raw=None):
    ##     self.version = version
    ##     self.prev_block = hexify (prev_block, True)
    ##     self.merkle_root = merkle_root
    ##     self.timestamp = timestamp
    ##     self.bits = bits
    ##     self.nonce = nonce
    ##     self.transactions = transactions
    ##     self.raw = raw

    def make_TX (self):
        return TX()

    def check_bits (self):
        shift  = self.bits >> 24
        target = (self.bits & 0xffffff) * (1 << (8 * (shift - 3)))
        hash = self.get_hash (hex=False)[::-1]
        val = int (hash.encode ('hex'), 16)
        return val < target

    def get_merkle_hash (self):
        hl = [dhash (t.raw) for t in self.transactions]
        while 1:
            if len(hl) == 1:
                return hl[0]
            if len(hl) % 2 != 0:
                hl.append (hl[-1])
            hl0 = []
            for i in range (0, len (hl), 2):
                hl0.append (dhash (hl[i] + hl[i+1]))
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

    def get_hash (self, hex=True):
        header = self.raw[:80]
        # dhash it
        hash = dhash (header)
        if hex:
            return hexify (hash)
        else:
            return hash

# --------------------------------------------------------------------------------
# block_db file format: (<8 bytes of size> <block>)+

ZERO_BLOCK = '00' * 32

class block_db:

    def __init__ (self, read_only=False):
        self.read_only = read_only
        self.blocks = {}
        self.prev = {}
        self.next = {}
        self.block_num = {}
        self.num_block = {}
        self.last_block = 0
        self.build_block_chain()
        self.file = None

    def get_header (self, name):
        path = os.path.join ('blocks', name)
        return open (path).read (80)

    # block can have only one previous block, but may have multiple
    #  next blocks.
    def build_block_chain (self):
        if not os.path.isfile (BLOCKS_PATH):
            open (BLOCKS_PATH, 'wb').write('')
        file = open (BLOCKS_PATH, 'rb')
        print 'reading block headers...'
        file.seek (0)
        i = -1
        name = ZERO_BLOCK
        # first, read all the blocks
        t0 = timer()
        while 1:
            pos = file.tell()
            size = file.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
                header = file.read (80)
                (version, prev_block, merkle_root,
                 timestamp, bits, nonce) = caesure.proto.unpack_block_header (header)
                # skip the rest of the block
                file.seek (size-80, 1)
                prev_block = hexify (prev_block, True)
                name = hexify (dhash (header), True)
                self.prev[name] = prev_block
                self.next.setdefault (prev_block, set()).add (name)
                i += 1
                self.block_num[name] = i
                self.num_block.setdefault (i, set()).add (name)
                self.blocks[name] = pos
        self.last_block = i
        print 'last block (%d): %s' % (i, name)
        file.close()
        print '%.02f secs to load block chain' % (t0.end())
        self.read_only_file = open (BLOCKS_PATH, 'rb')

    def open_for_append (self):
        # reopen in append mode
        self.file = open (BLOCKS_PATH, 'ab')

    def get_block (self, name):
        pos =  self.blocks[name]
        self.read_only_file.seek (pos)
        size = self.read_only_file.read (8)
        size, = struct.unpack ('<Q', size)
        return self.read_only_file.read (size)

    def __getitem__ (self, name):
        b = BLOCK()
        b.unpack (self.get_block (name))
        return b

    def by_num (self, num):
        # fetch *one* of the set, beware all callers of this
        return self[list(self.num_block[num])[0]]

    def add (self, name, block):
        if self.blocks.has_key (name):
            print 'ignoring block we already have:', name
        elif not self.block_num.has_key (block.prev_block) and block.prev_block != ZERO_BLOCK:
            # if we don't have the previous block, there's no
            #  point in remembering it at all.  toss it.
            pass
        else:
            self.write_block (name, block)

    def write_block (self, name, block):
        if self.file is None:
            self.open_for_append()
        size = len (block.raw)
        pos = self.file.tell()
        self.file.write (struct.pack ('<Q', size))
        self.file.write (block.raw)
        self.file.flush()
        self.prev[name] = block.prev_block
        self.next.setdefault (block.prev_block, set()).add (name)
        self.blocks[name] = pos
        if block.prev_block == ZERO_BLOCK:
            i = -1
        else:
            i = self.block_num[block.prev_block]
        self.block_num[name] = i+1
        self.num_block.setdefault (i+1, set()).add (name)
        self.last_block = i+1
        if the_wallet:
            # XXX: only if it's in the chain
            the_wallet.new_block (block)

    def has_key (self, name):
        return self.prev.has_key (name)

# --------------------------------------------------------------------------------
#                               protocol
# --------------------------------------------------------------------------------

class BadState (Exception):
    pass

# we need a way to do command/response on the connection, and we need to do something
#   to handle asynchronous commands (like continual inv) as well.  So I think we
#   need a mechanism to identify which things are waiting for responses (hopefully
#   the protocol makes this easy?).
#
# how to distinguish the answer we expected from an async one?  can we do it at the
#   protocol level?
#   addr: in response to getaddr: ok this one we can consider to not be command/response?
#   inv: this one I think we can figure out by checking the answer?

# commands are getblocks, getheaders.  we've never used getheaders, so the only
#   ACTUAL command is getblocks.  hmmm.. maybe that's why I did this async?
#
# so we can make a fifo/cv/etc for managing the getblocks/inv/etc 

# messages:            expect-async?   command    response   response-to
# 3.1 version                *            X           
# 3.2 verack                                          X        version
# 3.3 addr                   X                        X        getaddr
# 3.4 inv                    X                        X        getblocks
# 3.5 getdata                                         X        inv
# 3.6 notfound                                        X        getdata
# 3.7 getblocks                           X
# 3.8 getheaders                          X
# 3.9 tx                                              X        getdata
# 3.10 block                                          X        getdata
# 3.11 headers                                        X        getheaders
# 3.12 getaddr                            X

# for IP transactions (used?)
# 3.13 checkorder
# 3.14 submitorder
# 3.15 reply

# 3.16 ping                  X             
# 3.18 alert                 X


# ignore for now?
# 3.17 filterload, filteradd, filterclear, merkleblock

# the only totally unsolicited packets we expect are <addr>, <inv>

# I'd like to make downloading the block chain very fast if possible, by spreading
#   the load over many connections.  The problem with this is coordinating the streams
#   of blocks so that we get them in the order we need (otherwise any out of order block
#   would have to be discarded).  Making this particularly tricky is that the blocks
#   themselves do not know their height.  So we need to
#
#  1) collect an accurate list of blocks - in order
#  2) solicit those blocks from various connections
#  3) make sure to feed this to the block db in strict order.
#
# Let's review the process of discovering and fetching blocks
#
# 1) we send a <getblocks> command
# 2) we get anv <inv> reply with up to 500 block hashes in it
# 3) we send a <getdata> command with up to N block requests
# 4) we get N <block> commands back (presumably in order)
# 5) rinse, lather, repeat

# I think we can parallelize the block-fetching, but we should probably
#   stick with a serialized getblocks from just one connection.
#
# One super-annoyance with this whole process is the unwanted receipt of unsolicited
#   <inv> and <block> commands from a connection that we're not ready on yet - how
#   can we distinguish the ones we *want* from the unsolicited ones?
#
# Ah, here's another idea - we could request the blocks in backward order?  Hmmm...
#   would really suck for laying them down on disk though.  Maybe we can have a layer
#   that catches the blocks as they come in and assembles the chain on the fly?  I.e.,
#   unpack the block objects, put them into a 'ready for disk' map?  Then maybe have
#   another thread that's waiting for the right hashes to show up?
#
# Difficulty here - we do not know for sure if/when/how a block will chain until we
#   have downloaded it.  So basically we should just collect all incoming blocks into
#   memory, and somehow lay them down on disk as we discover their order.
# Now, what do we do if a block comes up missing... i.e., we request a block but the
#   other side never gives it to us (they close the connection, or are rude)?  Man, it'd
#   be nice to have some kind of request/timeout/rpc-like thing so we could tell when
#   this happens.  The protocol just isn't amenable to it, though.  Sigh.
#
# let's imagine what the holding pen would look like.
# first it'd have to have a notion of the 'bottom' - the last block we put on disk.
# then we have a map of blocks by predecessor hash?  So as soon as we put one in there
# that's one-up-from-bottom we wake up the disk thread.  Ah, I like this - it's very
# push-vs-pull-parser-thing.  Ahhhhhh... I think this would also solve our other problem,
#  maybe if the disk thread waits too long it somehow kicks the process? [like, it's waiting
#  on a particular block to show up?]
#
# so, maybe slowly coming together here...
# disk thread: starts up a loop like this:
#    for i in range (lo_block, hi_block):
#        b = wait_for_block (i)
#        db.add_block (b)
#
# the connection threads are all collecting blocks, throwing them into this map,
#   and checking to see if the one showing up is the one the disk thread is waiting on...
#
# so here's a good question - when do we know to emit getblocks()?  it'd be nice to do it
#   without having to wait too long... oh oh, I know... we have a set of blocks (from getblocks)
#   that we know we're waiting on... when this set gets below a threshold we emit another getblocks
#   command?
#
# so two different block maps:
# 1) the set of blocks whose bodies we have not yet requested
# 2) the set of blocks we have received, but not put on disk
#
# which threads are needed?
# 1) disk thread - waiting to write blocks to disk
# 2) connection threads
# 3) purgatory thread - this will emit getblocks/getdata calls, while also deciding which connections
#    to send them on (probably at random?) and whether to do it in parallel?
#
# purgatory thread can maybe manage the number of in-flight requests?
#
# how much of this needs to change for normal operation?  how much can stay in place?
# disk thread - I like this
# purgatory - I like this as well, a place to dump unconnected blocks?
#
# maybe the purgatory thread just exits once it catches up?  then the rest just falls into normal
#  operation?
# OR purgatory thread exits the 'populate' loop and enters a new loop waiting for generated blocks?
#
# BIG POINT: normal vs catchup behavior VERY DIFFERENT - we don't want to be validating/verifying/forwarding
#   the blocks we receive whilst catching up!
#
#
# unchained is an object holding blocks in memory.  whenever a block is added to unchained, the
#   'bottom' hash is check to see if it's the one the disk thread is waiting for.  This gets updated
#   and churned.
#
# 

class base_connection:

    # protocol was changed to reflect *protocol* version, not bitcoin-client-version
    version = 60002 # trying to update protocol from 60001 mar 2013

    def __init__ (self, addr='127.0.0.1', port=BITCOIN_PORT):
        self.addr = addr
        self.port = port
        self.nonce = make_nonce()
        self.conn = coro.tcp_sock()
        self.packet_count = 0
        self.stream = coro.read_stream.sock_stream (self.conn)

    def send_packet (self, command, payload):
        lc = len(command)
        assert (lc < 12)
        cmd = command + ('\x00' * (12 - lc))
        h = dhash (payload)
        checksum, = struct.unpack ('<I', h[:4])
        packet = struct.pack (
            '<4s12sII',
            BITCOIN_MAGIC,
            cmd,
            len(payload),
            checksum
            ) + payload
        self.conn.send (packet)

    def send_version (self):
        data = struct.pack ('<IQQ', self.version, 1, int(time.time()))
        data += pack_net_addr ((1, (self.addr, self.port)))
        data += pack_net_addr ((1, (my_addr, BITCOIN_PORT)))
        data += struct.pack ('<Q', self.nonce)
        data += pack_var_str ('/caesure:20130306/')
        start_height = the_block_db.last_block
        if start_height < 0:
            start_height = 0
        # ignore bip37 for now - leave True
        data += struct.pack ('<IB', start_height, 1)
        self.send_packet ('version', data)

    def gen_packets (self):
        while 1:
            data = self.stream.read_exact (24)
            if not data:
                W ('connection closed.\n')
                break
            magic, command, length, checksum = struct.unpack ('<I12sII', data)
            command = command.strip ('\x00')
            W ('cmd: %r\n' % (command,))
            self.packet_count += 1
            self.header = magic, command, length
            # XXX verify checksum
            if length:
                payload = self.stream.read_exact (length)
            else:
                payload = ''
            yield (command, payload)

    def getblocks (self):
        hashes = self.set_for_getblocks()
        hashes.append ('\x00' * 32)
        payload = ''.join ([
            struct.pack ('<I', self.version),
            pack_var_int (len(hashes)-1), # count does not include hash_stop
            ] + hashes
            )
        self.send_packet ('getblocks', payload)

    # see https://en.bitcoin.it/wiki/Satoshi_Client_Block_Exchange
    # "The getblocks message contains multiple block hashes that the
    #  requesting node already possesses, in order to help the remote
    #  note find the latest common block between the nodes. The list of
    #  hashes starts with the latest block and goes back ten and then
    #  doubles in an exponential progression until the genesis block is
    #  reached."

    def set_for_getblocks (self):
        db = the_block_db
        n = db.last_block
        result = []
        i = 0
        step = 1
        while n > 0:
            name = list(db.num_block[n])[0]
            result.append (unhexify (name, flip=True))
            n -= step
            i += 1
            if i >= 10:
                step *= 2
        return result
    
    def getdata (self, what):
        "request (TX|BLOCK)+ from the other side"
        payload = [pack_var_int (len(what))]
        for kind, name in what:
            # decode hash
            h = unhexify (name, flip=True)
            payload.append (struct.pack ('<I32s', kind, h))
        self.send_packet ('getdata', ''.join (payload))

class connection (base_connection):

    def __init__ (self, addr='127.0.0.1', port=BITCOIN_PORT):
        base_connection.__init__ (self, addr, port)
        self.seeking = []
        self.pending = {}
        if not the_block_db.prev:
            # totally empty block database, seek the genesis block
            self.seeking.append (genesis_block_hash)
        coro.spawn (self.go)

    def go (self):
        self.conn.connect ((self.addr, self.port))
        try:
            the_connection_list.append (self)
            self.send_version()
            for command, payload in self.gen_packets():
                self.do_command (command, payload)
        finally:
            the_connection_list.remove (self)
            self.conn.close()

    def check_command_name (self, command):
        for ch in command:
            if ch not in string.letters:
                return False
        return True

    def do_command (self, cmd, data):
        if self.check_command_name (cmd):
            try:
                method = getattr (self, 'cmd_%s' % cmd,)
            except AttributeError:
                W ('no support for "%s" command\n' % (cmd,))
            else:
                try:
                    method (data)
                except:
                    W ('caesure error: %r\n' % (coro.compact_traceback(),))
                    W ('     ********** problem processing %r command\n' % (cmd,))
        else:
            W ('bad command: "%r", ignoring\n' % (cmd,))

    max_pending = 50

    def kick_seeking (self):
        if len (self.seeking) and len (self.pending) < self.max_pending:
            ask, self.seeking = self.seeking[:self.max_pending], self.seeking[self.max_pending:]
            what = [(OBJ_BLOCK, name) for name in ask]
            print 'requesting %d blocks' % (len (ask),)
            self.getdata (what)
        if the_block_db.last_block == -1:
            # we already requested the genesis block, hold off...
            pass
        elif the_block_db.last_block < self.other_version.start_height:
            # we still need more blocks
            if not len (self.pending):
                self.getblocks()

    def cmd_version (self, data):
        # packet traces show VERSION, VERSION, VERACK, VERACK.
        self.other_version = caesure.proto.unpack_version (data)
        self.send_packet ('verack', '')

    def cmd_verack (self, data):
        if not len(the_block_db.blocks):
            self.seeking = [genesis_block_hash]
        self.kick_seeking()

    def cmd_addr (self, data):
        addr = caesure.proto.unpack_addr (data)
        print addr

    def cmd_inv (self, data):
        pairs = caesure.proto.unpack_inv (data)
        # request those blocks we don't have...
        seeking = []
        for objid, hash in pairs:
            if objid == OBJ_BLOCK:
                name = hexify (hash, True)
                if not the_block_db.has_key (name):
                    self.seeking.append (name)
        self.kick_seeking()

    def cmd_getdata (self, data):
        return caesure.proto.unpack_getdata (data)

    def cmd_tx (self, data):
        return caesure.proto.make_tx (data)

    def cmd_block (self, data):
        global last_block
        # the name of a block is the hash of its 'header', which
        #  lives in the first 80 bytes.
        name = hexify (dhash (data[:80]), True)
        # were we waiting for this block?
        if self.pending.has_key (name):
            del self.pending[name]
        b = BLOCK()
        b.unpack (data)
        last_block = b
        try:
            b.check_rules()
        except BadBlock as reason:
            print "*** bad block: %s %r" % (name, reason,)
        else:
            the_block_db.add (name, b)
        self.kick_seeking()

    def cmd_ping (self, data):
        # do nothing
        pass

    def cmd_alert (self, data):
        pos = position()
        payload   = unpack_var_str (data, pos)
        signature = unpack_var_str (data, pos)
        # XXX verify signature
        W ('alert: sig=%r payload=%r\n' % (signature, payload,))

the_wallet = None
the_block_db = None
the_connection_list = []

# Mar 2013 fetched from https://github.com/bitcoin/bitcoin/blob/master/src/net.cpp
dns_seeds = [
    "bitseed.xf2.org",
    "dnsseed.bluematt.me",
    "seed.bitcoin.sipa.be",
    "dnsseed.bitcoin.dashjr.org",
    ]

def valid_ip (s):
    try:
        parts = s.split ('.')
        nums = map (int, parts)
        assert (len (nums) == 4)
        for num in nums:
            if num > 255:
                raise ValueError
    except:
        raise ValueError ("not a valid IP: %r" % (s,))

def dns_seed():
    print 'fetching DNS seed addresses...'
    addrs = set()
    for name in dns_seeds:
        for info in socket.getaddrinfo (name, 8333):
            family, type, proto, _, addr = info
            if family == socket.AF_INET and type == socket.SOCK_STREAM and proto == socket.IPPROTO_TCP:
                addrs.add (addr[0])
    print '...done.'
    return addrs

if __name__ == '__main__':
    if '-t' in sys.argv:
        BITCOIN_PORT = 18333
        BITCOIN_MAGIC = '\xfa\xbf\xb5\xda'
        BLOCKS_PATH = 'blocks.testnet.bin'
        genesis_block_hash = '00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008'

    # mount the block database
    the_block_db = block_db()
    network = False

    if '-w' in sys.argv:
        i = sys.argv.index ('-w')
        the_wallet = wallet (sys.argv[i+1])

    # client mode
    if '-c' in sys.argv:
        i = sys.argv.index ('-c')
        [my_addr, other_addr] = sys.argv[i+1:i+3]
        bc = connection (other_addr)
        network = True

    # network mode
    if '-n' in sys.argv:
        i = sys.argv.index ('-n')
        my_addr = sys.argv[i+1]
        addrs = dns_seed()
        for addr in addrs:
            connection (addr)
        network = True

    do_monitor = '-m' in sys.argv
    do_admin   = '-a' in sys.argv

    if network:
        if do_monitor:
            import coro.backdoor
            coro.spawn (coro.backdoor.serve, unix_path='/tmp/caesure.bd')
        if do_admin:
            import coro.http
            import webadmin
            import zlib
            h = coro.http.server()
            coro.spawn (h.start, (('127.0.0.1', 8380)))
            h.push_handler (webadmin.handler())
            h.push_handler (coro.http.handlers.coro_status_handler())
            h.push_handler (coro.http.handlers.favicon_handler (zlib.compress (webadmin.favicon)))
        coro.event_loop()
    else:
        # database browsing mode
        db = the_block_db # alias
