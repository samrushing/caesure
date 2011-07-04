# -*- Mode: Python -*-

# A prototype bitcoin implementation.
#
# Author: Sam Rushing. http://www.nightmare.com/~rushing/
# July 2011.
#
# Status: much of the protocol is done.  The crypto bits are now
#   working, and I can verify 'standard' address-to-address transactions.
#   There's a simple wallet implementation, which will hopefully soon
#   be able to transact actual bitcoins.
# Todo: consider implementing the scripting engine.
# Todo: actually participate in the p2p network rather than being a lurker.
#
# One of my goals here is to keep the implementation as simple and small
#   as possible - with as few outside dependencies as I can get away with.
#   For that reason I'm using ctypes to get to openssl rather than building
#   in a dependency on M2Crypto or any of the other crypto packages.

import copy
import hashlib
import random
import struct
import socket
import time
import os
import string
import sys

import ctypes
import ctypes.util

import asyncore
import asynchat

from hashlib import sha256
from pprint import pprint as pp

W = sys.stderr.write

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

#'1Ncui8YjT7JJD91tkf42dijPnqywbupf7w'
#'\xed%3\x12/\xfd\x7f\x07$\xc4$Y\x92\x06\xcc\xb2>\x89\xd6\xf7'

def key_to_address (s):
    checksum = dhash ('\x00' + s)[:4]
    return '1' + base58_encode (
        int ('0x' + (s + checksum).encode ('hex_codec'), 16)
        )

def address_to_key (s):
    # strip off leading '1'
    s = ('%x' % base58_decode (s[1:])).decode ('hex_codec')
    hash160, check0 = s[:-4], s[-4:]
    check1 = dhash ('\x00' + hash160)[:4]
    if check0 != check1:
        raise BadAddress (s)
    return hash160

# for some reason many hashes are reversed, dunno why.  [this may just be block explorer]
# XXX figure out how to nip this as early as possible so we can use encode/decode.
def hexify (s, flip=False):
    if flip:
        return s[::-1].encode ('hex_codec')
    else:
        return s.encode ('hex_codec')

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex_codec')[::-1]
    else:
        return s.decode ('hex_codec')

def frob_hash (s):
    r = []
    for i in range (0, len (s), 2):
        r.append (s[i:i+2])
    r.reverse()
    return ''.join (r)

# wallet file format: (<8 bytes of size> <private-key>)+
class wallet:

    def __init__ (self, path):
        self.path = path
        self.keys = {}
        self.addrs = {}
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
        return addr

    def check_tx (self, tx):
        # did we receive any moneys?
        i = 0
        rtotal = 0
        for value, oscript in tx.outputs:
            addr = parse_oscript (oscript)
            if addr and self.addrs.has_key (addr):
                value = divmod (value, 100000000)
                print 'RECV: value=%d.%08d addr=%r index=%d' % (value[0], value[1], addr, i)
                rtotal += 1
                self.mine.append ((tx, i))
            i += 1
        # did we send money somewhere?
        for outpoint, iscript, sequence in tx.inputs:
            sig, pubkey = parse_iscript (iscript)
            if sig and pubkey:
                addr = key_to_address (rhash (pubkey))
                if self.addrs.has_key (addr):
                    print 'SEND: %r' % (tx,)
                    #import pdb; pdb.set_trace()
        return rtotal

    def scan_block_chain (self, start=129666): # 134586):
        # scan the whole chain for an TX related to this wallet
        self.mine = []
        db = the_block_db
        blocks = db.num_block.keys()
        blocks.sort()
        total = 0
        for num in blocks:
            if num >= start:
                block = db[db.num_block[num]]
                b = unpack_block (block)
                for tx in b.transactions:
                    total += self.check_tx (tx)
        print 'found %d txs' % (total,)

    def __getitem__ (self, addr):
        pubkey = self.addrs[addr]
        key = self.keys[pubkey]
        k = KEY()
        k.set_privkey (key)
        return k
    
# --------------------------------------------------------------------------------
#        ECDSA
# --------------------------------------------------------------------------------

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl'))

# this specifies the curve used with ECDSA.
NID_secp256k1 = 714 # from openssl/obj_mac.h

class KEY:

    def __init__ (self):
        self.k = ssl.EC_KEY_new_by_curve_name (NID_secp256k1)

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

    def verify (self, hash, sig):
        return ssl.ECDSA_verify (0, hash, len(hash), sig, len(sig), self.k)

# --------------------------------------------------------------------------------

genesis_block_hash = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

OBJ_TX    = 1
OBJ_BLOCK = 2

object_types = {
    0: "ERROR",
    1: "TX",
    2: "BLOCK"
    }

# used to keep track of the parsing position when cracking packets
class position:
    def __init__ (self, val=0):
        self.val = val
    def __int__ (self):
        return self.val
    def __index__ (self):
        return self.val
    def incr (self, delta):
        self.val += delta
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
    port, = struct.unpack ('!H', port) # pos adjusted above
    return services, (addr, port)

def pack_net_addr ((services, (addr, port))):
    addr = pack_ip_addr (addr)
    port = struct.pack ('!H', port)
    return struct.pack ('<Q', services) + addr + port

def make_nonce():
    return random.randint (0, 1<<64L)

def pack_version (me_addr, you_addr, nonce):
    data = struct.pack ('<IQQ', 31900, 1, int(time.time()))
    data += pack_net_addr ((1, you_addr))
    data += pack_net_addr ((1, me_addr))
    data += struct.pack ('<Q', nonce)
    data += pack_var_str ('')
    data += struct.pack ('<I', the_block_db.last_block_index)
    return make_packet ('version', data)

# *today*, every script is pretty much the same:
# tx script does this: push 73 bytes, push 65 bytes.
# pk_script does: OP_DUP, OP_HASH160, push 20 bytes, OP_EQUALVERIFY, OP_CHECKSIG
#
# XXX generation looks like an ip transaction, so they're not completely uncommon.

class TX:
    def __init__ (self, inputs, outputs, lock_time):
        self.inputs = inputs
        self.outputs = outputs
        self.lock_time = lock_time

    def dump (self):
        pass

    def copy (self):
        return copy.deepcopy (self)

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
    def verify (self, index):
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
        hash = dhash (to_hash)
        # now we have the hash for ecdsa.
        k = KEY()
        k.set_pubkey (pubkey)
        return k.verify (hash, sig)

def unpack_tx (data, pos):
    # has its own version number
    version, = unpack_pos ('<I', data, pos)
    if version != 1:
        raise ValueError ("unknown tx version: %d" % (version,))
    txin_count = unpack_var_int (data, pos)
    inputs = []
    outputs = []
    for i in range (txin_count):
        outpoint = unpack_pos ('<32sI', data, pos)
        script_length = unpack_var_int (data, pos)
        script = data[pos.val:pos.val+script_length]
        pos.incr (script_length)
        sequence, = unpack_pos ('<I', data, pos)
        parse_iscript (script)
        inputs.append ((outpoint, script, sequence))
    txout_count = unpack_var_int (data, pos)
    for i in range (txout_count):
        value, = unpack_pos ('<Q', data, pos)
        pk_script_length = unpack_var_int (data, pos)
        pk_script = data[pos.val:pos.val+pk_script_length]
        pos.incr (pk_script_length)
        parse_oscript (pk_script)
        outputs.append ((value, pk_script))
    lock_time, = unpack_pos ('<I', data, pos)
    return TX (inputs, outputs, lock_time)

def parse_iscript (s):
    # these tend to be push, push
    s0 = ord (s[0])
    if s0 > 0 and s0 < 76:
        # specifies the size of the first key
        k0 = s[1:1+s0]
        #print 'k0:', hexify (k0)
        if len(s) == 1+s0:
            return k0, None
        else:
            s1 = ord (s[1+s0])
            if s1 > 0 and s1 < 76:
                k1 = s[2+s0:2+s0+s1]
                #print 'k1:', hexify (k1)
                return k0, k1
            else:
                return None, None
    else:
        return None, None

def parse_oscript (s):
    if (ord(s[0]) == 118 and ord(s[1]) == 169 and ord(s[-2]) == 136 and ord(s[-1]) == 172):
        size = ord(s[2])
        addr = key_to_address (s[3:size+3])
        #print 'OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG' % addr
        return addr
    else:
        return None

# ok, figuring out how to verify tx.
# the input scripts contain the signature and public key.
# signature is DER-encoded ECDSA sig with a one-byte '\x01' suffix.

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

# will be used for packets other than verack
def make_packet (command, payload):
    assert (len(command) < 12)
    lc = len(command)
    cmd = command + ('\x00' * (12 - lc))
    if command == 'version':
        return struct.pack (
            '<I12sI',
            3652501241,
            cmd,
            len(payload),
            ) + payload
    else:
        h = dhash (payload)
        checksum = struct.unpack ('<I', h[:4])[0]
        return struct.pack (
            '<I12sII',
            3652501241,
            cmd,
            len(payload),
            checksum
            ) + payload

class proto_version:
    pass

def unpack_version (data):
    pos = position()
    v = proto_version()
    v.version, v.services, v.timestamp = unpack_pos ('<IQQ', data, pos)
    v.me_addr = unpack_net_addr (data, pos)
    v.you_addr = unpack_net_addr (data, pos)
    v.nonce = unpack_pos ('<Q', data, pos)
    v.sub_version_num = unpack_var_str (data, pos)
    v.start_height, = unpack_pos ('<I', data, pos)
    print pp (v.__dict__)
    return v

def unpack_inv (data, pos):
    count = unpack_var_int (data, pos)
    result = []
    for i in range (count):
        objid, hash = unpack_pos ('<I32s', data, pos)
        objid_str = object_types.get (objid, "Unknown")
        result.append ((objid, hash))
        print objid_str, hexify (hash, flip=True)
    return result

def unpack_addr (data):
    pos = position()
    count = unpack_var_int (data, pos)
    for i in range (count):
        # timestamp & address
        timestamp, = unpack_pos ('<I', data, pos)
        net_addr = unpack_net_addr (data, pos)
        print timestamp, net_addr

def unpack_getdata (data, pos):
    # identical to INV
    return unpack_inv (data, pos)

class BLOCK:
    def __init__ (self, prev_block, merkle_root, timestamp, bits, nonce, transactions):
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.transactions = transactions

def unpack_block (data, pos=None):
    if pos is None:
        pos = position()
    version, prev_block, merkle_root, timestamp, bits, nonce = unpack_pos ('<I32s32sIII', data, pos)
    if version != 1:
        raise ValueError ("unsupported block version: %d" % (version,))
    count = unpack_var_int (data, pos)
    transactions = []
    #print '----- block %d transactions ------' % (count,)
    for i in range (count):
        #print '    ----- block transaction #%d' % (i,)
        p0 = pos.val
        transactions.append (unpack_tx (data, pos))
        p1 = pos.val
        transactions[-1].raw = data[p0:p1]
    #print '----- end of block ------------------'
    return BLOCK (prev_block, merkle_root, timestamp, bits, nonce, transactions)

def unpack_block_header (data):
    # version, prev_block, merkle_root, timestamp, bits, nonce
    return struct.unpack ('<I32s32sIII', data)

# --------------------------------------------------------------------------------
# block_db file format: (<8 bytes of size> <block>)+

class block_db:

    def __init__ (self, read_only=False):
        self.read_only = read_only
        self.blocks = {}
        self.prev = {}
        self.next = {}
        self.block_num = {}
        self.num_block = {}
        self.last_block = '00' * 32
        self.build_block_chain()

    def get_header (self, name):
        path = os.path.join ('blocks', name)
        return open (path).read (80)

    def build_block_chain (self):
        if not os.path.isfile ('blocks.bin'):
            open ('blocks.bin', 'wb').write('')
        file = open ('blocks.bin', 'rb')
        print 'reading block headers...'
        file.seek (0)
        i = -1
        name = '00' * 32
        self.next[name] = genesis_block_hash
        self.prev[genesis_block_hash] = name
        self.block_num[genesis_block_hash] = 0
        self.num_block[0] = genesis_block_hash
        while 1:
            pos = file.tell()
            size = file.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
                header = file.read (80)
                (version, prev_block, merkle_root,
                 timestamp, bits, nonce) = unpack_block_header (header)
                # skip the rest of the block
                file.seek (size-80, 1)
                prev_block = hexify (prev_block, True)
                name = hexify (dhash (header), True)
                self.prev[name] = prev_block
                self.next[prev_block] = name
                i += 1
                self.block_num[name] = i
                self.num_block[i] = name
                self.blocks[name] = pos
        self.last_block = name
        self.last_block_index = i
        print 'last block (%d): %s' % (i, name)
        print len(self.blocks), len(self.prev), len (self.next), len (self.block_num), len (self.num_block)
        file.close()
        if not self.read_only:
            # reopen in append mode
            self.file = open ('blocks.bin', 'ab')
        self.read_only_file = open ('blocks.bin', 'rb')

    def __getitem__ (self, name):
        pos =  self.blocks[name]
        self.read_only_file.seek (pos)
        size = self.read_only_file.read (8)
        size, = struct.unpack ('<Q', size)
        return self.read_only_file.read (size)

    def add (self, name, block):
        if self.prev.has_key (name):
            print 'ignoring block we already have:', name
        else:
            (version, prev_block, merkle_root,
             timestamp, bits, nonce) = unpack_block_header (block[:80])
            prev_block = hexify (prev_block, True)
            if self.has_key (prev_block):
                size = len (block)
                pos = self.file.tell()
                self.file.write (struct.pack ('<Q', size))
                self.file.write (block)
                self.file.flush()
                self.prev[name] = prev_block
                self.next[prev_block] = name
                self.blocks[name] = pos
                print 'wrote block %s' % (name,)
                i = self.block_num[prev_block]
                self.block_num[name] = i+1
                self.num_block[i+1] = name
                self.last_block = name
                self.last_block_index = i+1
            else:
                print 'cannot chain block %s' % (name,)

    def has_key (self, name):
        return self.prev.has_key (name)

# --------------------------------------------------------------------------------
#                               protocol
# --------------------------------------------------------------------------------

VERACK = (
    '\xf9\xbe\xb4\xd9'               # magic
    'verack\x00\x00\x00\x00\x00\x00' # verackNUL...
    '\x00\x00\x00\x00'               # payload length == 0
    )

HEADER   = 0
CHECKSUM = 1
PAYLOAD  = 2

class BadState (Exception):
    pass

class asyn_conn (asynchat.async_chat):

    # my client version when I started this code
    version = 31900

    def __init__ (self, addr=('127.0.0.1', 8333)):
        self.nonce = make_nonce()
        self.conn = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        asynchat.async_chat.__init__ (self, self.conn)
        self.connect (addr)
        self.addr = addr
        self.ibuffer = []
        self.seeking = []
        self.pending = {}
        self.state_header()
        if not the_block_db.prev:
            # totally empty block database, seek the genesis block
            self.seeking.append (genesis_block_hash)
        self.push (pack_version ((my_addr, 8333), addr, self.nonce))

    def collect_incoming_data (self, data):
        self.ibuffer.append (data)

    def handle_connect (self):
        pass

    def state_header (self):
        self.state = HEADER
        self.set_terminator (20)

    def state_checksum (self):
        self.state = CHECKSUM
        self.set_terminator (4)

    def state_payload (self, length):
        if length > 0:
            self.state = PAYLOAD
            self.set_terminator (length)
        else:
            self.state_header()

    def check_command_name (self, command):
        for ch in command:
            if ch not in string.letters:
                return False
        return True

    def found_terminator (self):
        data, self.ibuffer = ''.join (self.ibuffer), []
        if self.state == HEADER:
            # ok, we got a header
            magic, command, length = struct.unpack ('<I12sI', data)
            command = command.strip ('\x00')
            print 'cmd:', command
            self.header = magic, command, length
            if command not in ('version', 'verack'):
                self.state_checksum()
            else:
                self.state_payload (length)
        elif self.state == CHECKSUM:
            magic, command, length = self.header
            self.checksum, = struct.unpack ('<I', data)
            # XXX actually verify the checksum, duh
            self.state_payload (length)
        elif self.state == PAYLOAD:
            magic, command, length = self.header
            if self.check_command_name (command):
                try:
                    method = getattr (self, 'cmd_%s' % command,)
                except AttributeError:
                    print 'no support for "%s" command' % (command,)
                else:
                    method (data)
            else:
                print 'bad command: "%r", ignoring' % (command,)
            self.state_header()
        else:
            raise BadState (self.state)
            
    def kick_seeking (self):
        if len (self.seeking) and len (self.pending) < 10:
            ask, self.seeking = self.seeking[:10], self.seeking[10:]
            payload = [pack_var_int (len(ask))]
            for name in ask:
                hash = unhexify (name, True)
                self.pending[name] = True
                payload.append (struct.pack ('<I32s', OBJ_BLOCK, hash))
            print 'requesting %d blocks' % (len (ask),)
            packet = make_packet ('getdata', ''.join (payload))
            self.push (packet)
        if the_block_db.last_block_index < self.other_version.start_height:
            # we still need more blocks
            self.getblocks()

    def getblocks (self):
        start = the_block_db.last_block
        payload = ''.join ([
            struct.pack ('<I', self.version),
            pack_var_int (1),
            unhexify (start, flip=True),
            '\x00' * 32,
            ])
        packet = make_packet ('getblocks', payload)
        self.push (packet)

    def cmd_version (self, data):
        # packet traces show VERSION, VERSION, VERACK, VERACK.
        self.other_version = unpack_version (data)
        self.push (VERACK)

    def cmd_addr (self, data):
        return unpack_addr (data)

    def cmd_inv (self, data):
        pairs = unpack_inv (data, position())
        # request those blocks we don't have...
        seeking = []
        for objid, hash in pairs:
            if objid == OBJ_BLOCK:
                name = hexify (hash, True)
                if not the_block_db.has_key (name):
                    self.seeking.append (name)
        self.kick_seeking()

    def cmd_getdata (self, data):
        return unpack_inv (data, position())

    def cmd_tx (self, data):
        return unpack_tx (data, position())

    def cmd_block (self, data):
        # the name of a block is the hash of its 'header', which
        #  lives in the first 80 bytes.
        name = hexify (dhash (data[:80]), True)
        # were we waiting for this block?
        if self.pending.has_key (name):
            del self.pending[name]
        the_block_db.add (name, data)
        self.kick_seeking()

# ================================================================================
#              commands meant to be used from the monitor
# ================================================================================

def connect (addr=('127.0.0.1', 8333)):
    global bitcoin_connection
    bitcoin_connection = asyn_conn (addr)

def close():
    global bitcoin_connection
    bitcoin_connection.close()
    bitcoin_connection = None

def getblocks():
    global bitcoin_connection
    if not bitcoin_connection:
        print 'no connection!'
    else:
        print 'requesting block chain...'
        # getblocks asks the other side for a *list* of blocks, up to 500 long.
        # to fetch those blocks you need to emit <getdata>.
        # (can we fetch the entire chain of just names?)
        # where do we start
        start = the_block_db.last_block
        payload = ''.join ([
            struct.pack ('<I', bitcoin_connection.version),
            pack_var_int (1),
            unhexify (start, flip=True),
            '\x00' * 32,
            ])
        packet = make_packet ('getblocks', payload)
        bitcoin_connection.push (packet)

def getdata (kind, name):
    global bitcoin_connection
    if not bitcoin_connection:
        print 'no connection!'
    else:
        kind = {'TX':1,'BLOCK':2}[kind.upper()]
        # decode hash
        hash = unhexify (name, flip=True)
        payload = [pack_var_int (1)]
        payload.append (struct.pack ('<I32s', kind, hash))
        packet = make_packet ('getdata', ''.join (payload))
        bitcoin_connection.push (packet)

def getblock (name):
    global bitcoin_connection
    if not bitcoin_connection:
        print 'no connection!'
    else:
        print 'requesting block chain...'
        payload = ''.join ([
            struct.pack ('<I', bitcoin_connection.version),
            pack_var_int (1),
            unhexify (start, flip=True),
            '\x00' * 32,
            ])
        packet = make_packet ('getblocks', payload)
        bitcoin_connection.push (packet)

# ================================================================================

def valid_ip (s):
    parts = s.split ('.')
    nums = map (int, parts)
    assert (len (nums) == 4)
    for num in nums:
        if num > 255:
            raise ValueError

the_wallet = None
the_block_db = None

if __name__ == '__main__':
    if '-w' in sys.argv:
        i = sys.argv.index ('-w')
        the_wallet = wallet (sys.argv[i+1])
        del sys.argv[i:i+2]
    # server mode
    if '-s' in sys.argv:
        sys.argv.remove ('-s')
        if len(sys.argv) < 2:
            print 'usage: %s -s <externally-visible-ip-address>' % (sys.argv[0],)
        else:
            my_addr = sys.argv[1]
            valid_ip (my_addr)
            import monitor
            # for now, there's a single global connection.  later we'll have a bunch.
            the_block_db = block_db()
            bitcoin_connection = None
            m = monitor.monitor_server()
            asyncore.loop()
    else:
        the_block_db = block_db (read_only=True)
        db = the_block_db       # alias
