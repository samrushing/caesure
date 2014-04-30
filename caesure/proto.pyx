# -*- Mode: Cython; indent-tabs-mode: nil -*-

import socket
from socket import AF_INET6, inet_ntop, inet_pton
from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t
from cpython.bytes cimport PyBytes_FromStringAndSize

from hashlib import sha256

def dhash (s):
    return sha256(sha256(s).digest()).digest()

# --------------------------------------------------------------------------------
# hexify
# --------------------------------------------------------------------------------

cdef char *hexdigits = "0123456789abcdef"

cdef _hexify (bytes s):
    cdef int slen = len (s)
    cdef bytes o = PyBytes_FromStringAndSize (NULL, slen * 2)
    cdef unsigned char * a = s
    cdef unsigned char * b = o
    cdef int i
    for i in range (slen):
        b[i*2]   = hexdigits[a[i] >> 4]
        b[i*2+1] = hexdigits[a[i] & 0xf]
    return o

cdef _flip_hexify (bytes s):
    cdef int slen = len (s)
    cdef bytes o = PyBytes_FromStringAndSize (NULL, slen * 2)
    cdef unsigned char * a = s
    cdef unsigned char * b = o
    cdef int i
    cdef int p
    for i in range (slen):
        p = (2*slen)-((i+1)*2)
        b[p]   = hexdigits[a[i] >> 4]
        b[p+1] = hexdigits[a[i] & 0xf]
    return o

def hexify (bytes s, bint flip=False):
    if flip:
        return _flip_hexify (s)
    else:
        return _hexify (s)

# --------------------------------------------------------------------------------
# base58
# --------------------------------------------------------------------------------

cdef char * b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
cdef dict b58_map = {}
cdef int i = 0
for dig in b58_digits:
    b58_map[dig] = i
    i += 1

def base58_encode (n):
    cdef char buf[512]
    cdef int i = 0
    while n > 0:
        n, r = divmod (n, 58)
        buf[511-i] = b58_digits[r]
        if i == 512:
            raise ValueError ("integer too large")
        i += 1
    return buf[512-i:512]

def base58_decode (bytes s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_map[ch]
        n += digit
    return n

# --------------------------------------------------------------------------------
# codec (well, decoder only right now)
# --------------------------------------------------------------------------------

cdef class pkt:
    cdef bytes data
    cdef unsigned char * d
    cdef int len
    cdef int pos

    def __init__ (self, bytes data):
        self.data = data
        self.d = data
        self.len = len(data)
        self.pos = 0
    
    cdef need (self, int n):
        if self.pos + n > self.len:
            raise IndexError (self.len, self.pos +n)

    cdef bytes remains (self):
        cdef bytes r
        r = self.d[self.pos:self.len]
        self.pos = self.len
        return r

    cdef uint8_t u8 (self) except? -1:
        cdef uint8_t r
        self.need (1)
        r = self.d[self.pos]
        self.pos += 1
        return r

    cdef uint16_t u16 (self) except? -1:
        cdef uint16_t r
        self.need (2)
        r = (self.d[self.pos+1] << 8) | self.d[self.pos] 
        self.pos += 2
        return r

    cdef uint16_t net_u16 (self) except? -1:
        cdef uint16_t r
        self.need (2)
        r = (self.d[self.pos+0] << 8) | self.d[self.pos+1] 
        self.pos += 2
        return r

    cdef uint32_t u32 (self) except? -1:
        cdef uint32_t r
        self.need (4)
        r = (  (self.d[self.pos+3] << 24)
             | (self.d[self.pos+2] << 16)
             | (self.d[self.pos+1] << 8)
             | (self.d[self.pos] ) )
        self.pos += 4
        return r

    cdef uint64_t u64 (self) except? -1:
        cdef uint64_t r = 0
        cdef int i
        self.need (8)
        for i in range (7,-1,-1):
            r <<= 8
            r |= self.d[self.pos+i]
        self.pos += 8
        return r

    cdef uint64_t unpack_var_int (self) except? -1:
        cdef uint8_t n0 = self.u8()
        if n0 < 0xfd:
            return n0
        elif n0 == 0xfd:
            return self.u16()
        elif n0 == 0xfe:
            return self.u32()
        else:
            return self.u64()

    cdef bytes unpack_str (self, uint64_t n):
        cdef bytes r
        self.need (n)
        r = self.d[self.pos:self.pos+n]
        self.pos += n
        return r

    cdef bytes unpack_var_str (self):
        cdef uint64_t n = self.unpack_var_int()
        return self.unpack_str (n)

    cdef unpack_net_addr (self):
        cdef uint64_t services = self.u64()
        cdef bytes addr = self.unpack_str (16)
        cdef uint16_t port = self.net_u16()
        addr = inet_ntop (AF_INET6, addr)
        if addr.startswith ('::ffff:'):
            addr = addr[7:]
        return services, (addr, port)

    cdef bint unpack_bool (self) except? -1:
        cdef bint r
        self.need (1)
        r = self.d[self.pos]
        self.pos += 1
        return r

# --------------------------------------------------------------------------------
# messages
# --------------------------------------------------------------------------------

cdef class VERSION:
    cdef public uint32_t version
    cdef public uint64_t services
    cdef public uint64_t timestamp
    cdef public object you_addr
    cdef public object me_addr
    cdef public uint64_t nonce
    cdef public bytes sub_version_num
    cdef public uint32_t start_height
    cdef public bint relay
    cdef public bytes extra
    
    def unpack (self, bytes data):
        cdef pkt p = pkt (data)
        self.version = p.u32()
        self.services = p.u64()
        self.timestamp = p.u64()
        self.you_addr = p.unpack_net_addr()
        self.me_addr = p.unpack_net_addr()
        self.nonce = p.u64()
        self.sub_version_num = p.unpack_var_str()
        self.start_height = p.u32()
        if self.version > 70001:
            self.relay = p.unpack_bool()
        if p.pos < p.len:
            self.extra = p.remains()
        else:
            self.extra = b''

    def pack (self):
        cdef list result = [
            pack_u32 (self.version),
            pack_u64 (self.services),
            pack_u64 (self.timestamp),
            pack_net_addr (self.you_addr),
            pack_net_addr (self.me_addr),
            pack_u64 (self.nonce),
            pack_var_int (len(self.sub_version_num)),
            self.sub_version_num,
            pack_u32 (self.start_height),
            pack_bool (self.relay),
            ]
        return b''.join (result)

    def dump (self, fout):
        fout.write (
            'VERSION {\n'
            '  version=%d\n'
            '  services=%d\n'
            '  timestamp=%d\n'
            '  you_addr=%r\n'
            '  me_addr=%r\n'
            '  nonce=%d\n'
            '  sub_version_num=%r\n'
            '  start_height=%d\n'
            '  }\n' % (
                self.version, self.services, self.timestamp, self.me_addr, self.you_addr,
                self.nonce, self.sub_version_num, self.start_height
                )
            )

cpdef bytes pack_u16 (uint16_t n):
    return chr(n & 0xff) + chr ((n>>8) &0xff)

cpdef bytes pack_net_u16 (uint16_t n):
    return chr ((n>>8) &0xff) + chr(n & 0xff)

cpdef bytes pack_u32 (uint32_t n):
    cdef int i
    cdef char r[4]
    for i in range (4):
        r[i] = n & 0xff
        n >>= 8
    return r[:4]

cpdef bytes pack_u64 (uint64_t n):
    cdef int i
    cdef char r[8]
    for i in range (8):
        r[i] = n & 0xff
        n >>= 8
    return r[:8]

cpdef bytes pack_var_int (uint64_t n):
    if n < 0xfd:
        return chr (<uint8_t>n)
    elif n <= 0xffff:
        return b'\xfd' + pack_u16 (<uint16_t>n)
    elif n <= 0xffffffff:
        return b'\xfe' + pack_u32 (<uint32_t>n)
    else:
        return b'\xff' + pack_u64 (n)

cpdef bytes pack_bool (bint b):
    if b:
        return b'\xff'
    else:
        return b'\x00'

def pack_ip_addr (addr):
    if '.' in addr:
        return socket.inet_pton (socket.AF_INET6, '::ffff:%s' % (addr,))
    elif ':' in addr:
        return socket.inet_pton (socket.AF_INET6, addr)
    else:
        raise ValueError (addr)

cpdef bytes pack_net_addr (addr):
    (services, (ip, port)) = addr
    cdef list result = [
        pack_u64 (services),
        pack_ip_addr (ip),
        pack_net_u16 (port),
        ]
    return b''.join (result)

cpdef bytes pack_addr (list addrs):
    cdef list result = [pack_var_int (len (addrs))]
    cdef uint32_t timestamp
    for timestamp, addr in addrs:
        result.append (pack_u32 (timestamp))
        result.append (pack_net_addr (addr))
    return b''.join (result)

cdef class TX:
    cdef public uint32_t version
    cdef public uint32_t lock_time
    cdef public list inputs
    cdef public list outputs
    cdef readonly bytes raw
    cdef readonly bytes name

    cdef unpack_input (self, pkt p):
        cdef bytes outpoint_hash = p.unpack_str (32)
        cdef uint32_t outpoint_index = p.u32()
        cdef uint64_t script_length = p.unpack_var_int()
        cdef bytes script = p.unpack_str (script_length)
        cdef uint32_t sequence = p.u32()
        return ((outpoint_hash, outpoint_index), script, sequence)

    cdef pack_input (self, list result, input):
        (outpoint_hash, outpoint_index), script, sequence = input
        result.extend ([
            outpoint_hash,
            pack_u32 (outpoint_index),
            pack_var_int (len (script)),
            script,
            pack_u32 (sequence),
            ])

    cdef unpack_output (self, pkt p):
        cdef uint64_t value = p.u64()
        cdef uint64_t pk_script_length = p.unpack_var_int()
        cdef bytes script = p.unpack_str (pk_script_length)
        return (value, script)

    cdef pack_output (self, list result, uint64_t value, bytes script):
        result.extend ([
            pack_u64 (value),
            pack_var_int (len (script)),
            script
            ])

    cdef unpack0 (self, pkt p):
        cdef uint64_t txin_count
        cdef uint64_t txout_count
        cdef int i
        self.inputs = []
        self.outputs = []
        self.version = p.u32()
        txin_count = p.unpack_var_int()
        for i in range (txin_count):
            self.inputs.append (self.unpack_input (p))
        txout_count = p.unpack_var_int()
        for i in range (txout_count):
            self.outputs.append (self.unpack_output (p))
        self.lock_time = p.u32()
            
    def pack (self):
        cdef int i
        cdef list result = [
            pack_u32 (self.version),
            pack_var_int (len (self.inputs))
            ]
        for input in self.inputs:
            self.pack_input (result, input)
        result.append (pack_var_int (len (self.outputs)))
        for i in range (len (self.outputs)):
            value, script = self.outputs[i]
            self.pack_output (result, value, script)
        result.append (pack_u32 (self.lock_time))
        return b''.join (result)

    # unpack1 only exists to capture self.raw during block unpacking
    cdef unpack1 (self, pkt p):
        cdef int pos0 = p.pos
        cdef int pos1
        self.unpack0 (p)
        pos1 = p.pos
        self.raw = p.data[pos0:pos1]
        self.name = self.get_name()

    def unpack (self, bytes data):
        self.raw = data
        self.name = self.get_name()
        return self.unpack0 (pkt (data))

    def get_name (self):
        return _flip_hexify (dhash (self.raw))

cdef class BLOCK:
    cdef public uint32_t version
    # XXX consider putting these here as char x[32]
    cdef public bytes prev_block
    cdef public bytes merkle_root
    cdef public uint32_t timestamp
    cdef public uint32_t bits    
    cdef public uint32_t nonce
    cdef public list transactions
    cdef readonly bytes raw
    cdef readonly bytes name
    
    def make_TX (self):
        return TX()

    def unpack (self, bytes data):
        cdef pkt p = pkt (data)
        cdef uint64_t tx_count
        cdef TX tx
        self.raw = data
        self.version = p.u32()
        self.prev_block = _flip_hexify (p.unpack_str (32))
        self.merkle_root = p.unpack_str (32)
        self.timestamp = p.u32()
        self.bits = p.u32()
        self.nonce = p.u32()
        tx_count = p.unpack_var_int()
        self.transactions = []
        cdef int i
        for i in range (tx_count):
            tx = self.make_TX()
            tx.unpack1 (p)
            self.transactions.append (tx)
        self.name = self.get_name()

    def get_name (self):
        cdef bytes header = self.raw[:80]
        return _flip_hexify (dhash (header))

def unpack_block_header (bytes data):
    cdef pkt p = pkt (data)
    raw = data
    version = p.u32()
    prev_block = p.unpack_str (32)
    merkle_root = p.unpack_str (32)
    timestamp = p.u32()
    bits = p.u32()
    nonce = p.u32()
    return (version, prev_block, merkle_root, timestamp, bits, nonce)

def make_block (data):
    b = BLOCK()
    b.unpack (data)
    return b

def make_tx (data):
    tx = TX()
    tx.unpack (data)
    return tx

def unpack_version (data):
    v = VERSION()
    v.unpack (data)
    return v

def unpack_inv (data):
    cdef pkt p = pkt (data)
    cdef uint64_t count = p.unpack_var_int()
    cdef list result = []
    cdef int i
    for i in range (count):
        obj_id = p.u32()
        obj_hash = p.unpack_str (32)
        result.append ((obj_id, obj_hash))
    return result

def unpack_addr (data):
    cdef pkt p = pkt (data)
    cdef uint64_t count = p.unpack_var_int()
    cdef list result = []
    cdef int i
    cdef uint32_t timestamp
    for i in range (count):
        result.append ((p.u32(), p.unpack_net_addr()))
    return result
        
def unpack_getdata (data):
    return unpack_inv (data)

def unpack_alert (data):
    cdef pkt p = pkt (data)
    cdef bytes payload = p.unpack_var_str()
    cdef bytes signature = p.unpack_var_str()
    return payload, signature
