# -*- Mode: Python -*-

import hashlib
import random
import struct
import socket
import time
import os
import string
import sys

import asyncore
import asynchat

# probably use one of these to get ECDSA:
#import ecdsa
#import M2Crypto

from hashlib import sha256
from pprint import pprint as pp

W = sys.stderr.write

b58_digits = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'

def base58_encode (n):
    l = []
    while n > 0:
        n, r = divmod (n, 58)
        l.insert (0, (b58_digits[r]))
    return ''.join (l)

def dhash (s):
    return sha256(sha256(s).digest()).digest()

def rhash (s):
    h0 = sha256 (s)
    h1 = hashlib.new ('ripemd160')
    h1.update (h0.digest())
    return h1.digest()

def dhash_check (h):
    return struct.unpack ('<I', h[:4])[0]

# for some reason many hashes are reversed, dunno why.
def hexify (s, flip=False):
    r = ['%02x' % ord (ch) for ch in s]
    if flip:
        r.reverse()
    return ''.join (r)

def unhexify (s, flip=False):
    r = []
    for i in range (0, len (s), 2):
        r.append (chr (string.atoi (s[i:i+2], 16)))
    if flip:
        r.reverse()
    return ''.join (r)

def frob_hash (s):
    r = []
    for i in range (0, len (s), 2):
        r.append (s[i:i+2])
    r.reverse()
    return ''.join (r)

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

def pack_version (other, nonce):
    data = struct.pack ('<IQQ', 31900, 1, int(time.time()))
    data += pack_net_addr (other.you_addr)
    data += pack_net_addr (other.me_addr)
    data += struct.pack ('<Q', nonce)
    data += pack_var_str ('')
    data += struct.pack ('<I', the_block_db.last_block_index)
    return make_packet ('version', data)

# *today*, every script is pretty much the same:
# tx script does this: push 73 bytes, push 65 bytes.
# pk_script does: OP_DUP, OP_HASH160, push 20 bytes, OP_EQUALVERIFY, OP_CHECKSIG

def unpack_tx (data, pos):
    # has its own version number
    version, = unpack_pos ('<I', data, pos)
    print 'tx version=', version
    txin_count = unpack_var_int (data, pos)
    print 'txin_count=', txin_count
    for i in range (txin_count):
        print 'input #%d' % (i,)
        outpoint = unpack_pos ('<32sI', data, pos)
        script_length = unpack_var_int (data, pos)
        script = data[pos.val:pos.val+script_length]
        pos.incr (script_length)
        sequence, = unpack_pos ('<I', data, pos)
        print 'outpoint=', (hexify (outpoint[0]), outpoint[1])
        print 'script_length=', script_length
        print 'script=', hexify (script)
        print 'sequence=', sequence
    txout_count = unpack_var_int (data, pos)
    for i in range (txout_count):
        print 'output #%d' % (i,)
        value, = unpack_pos ('<Q', data, pos)
        pk_script_length = unpack_var_int (data, pos)
        pk_script = data[pos.val:pos.val+pk_script_length]
        pos.incr (pk_script_length)
        print 'value = %d.%08d' % divmod (value, 100000000)
        print 'pk_script_length=', pk_script_length
        print 'pk_script=', hexify (pk_script)
    lock_time, = unpack_pos ('<I', data, pos)
    print 'lock_time=', lock_time

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
    assert len(cmd) == 12
    if command == 'version':
        return struct.pack (
            '<I12sI',
            3652501241,
            cmd,
            len(payload),
            ) + payload
    else:
        h = dhash (payload)
        checksum = dhash_check (h)
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

def unpack_block (data, pos):
    version, prev_block, merkle_root, timestamp, bits, nonce = unpack_pos ('<I32s32sIII', data, pos)
    count = unpack_var_int (data, pos)
    print '----- block %d transactions ------' % (count,)
    for i in range (count):
        print '    ----- block transaction #%d' % (i,)
        unpack_tx (data, pos)
    print '----- end of block ------------------'

def unpack_block_header (data):
    # version, prev_block, merkle_root, timestamp, bits, nonce
    return struct.unpack ('<I32s32sIII', data)

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

class link:
    def __init__ (self, name):
        self.name = name
        self.next = None
        self.prev = None

class block_db:

    def __init__ (self):
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
        # reopen in append mode
        self.file = open ('blocks.bin', 'ab')

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

the_block_db = block_db()

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
        self.push (pack_version (self.other_version, self.nonce))
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

def connect():
    global bitcoin_connection
    bitcoin_connection = asyn_conn()

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

if __name__ == '__main__':
    # server mode
    if '-s' in sys.argv:
        import monitor
        # for now, there's a single global connection.  later we'll have a bunch.
        bitcoin_connection = None
        c = command_server()
        m = monitor.monitor_server()
        asyncore.loop()
    else:
        pass
