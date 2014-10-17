# -*- Mode: Python -*-

import hashlib
import struct
from pprint import pprint as pp
import sys

from caesure._script import *

W = sys.stderr.write

# confusion: I believe 'standard' transactions != 'valid scripts', I think They
#  have chosen a subset of legal transactions that are considered 'standard'.

# status: passes the 'valid' unit tests from bitcoin/bitcoin, but does
#   not yet fail all the 'invalid' tests. [mostly constraints like op
#   count, stack size, etc...]

class OPCODES:
    # push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99
    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4
    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_NOP2 = 0xb1
    OP_NOP3 = 0xb2
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    # template matching params
    OP_SMALLINTEGER = 0xfa
    OP_PUBKEYS = 0xfb
    OP_PUBKEYHASH = 0xfd
    OP_PUBKEY = 0xfe

    OP_INVALIDOPCODE = 0xff

opcode_map_fwd = {}
opcode_map_rev = {}

for name in dir(OPCODES):
    if name.startswith ('OP_'):
        val = getattr (OPCODES, name)
        globals()[name] = val
        opcode_map_fwd[name] = val
        opcode_map_rev[val] = name

def render_int (n):
    # little-endian byte stream
    if n < 0:
        neg = True
        n = -n
    else:
        neg = False
    r = []
    while n:
        r.append (n & 0xff)
        n >>= 8
    if neg:
        if r[-1] & 0x80:
            r.append (0x80)
        else:
            r[-1] |= 0x80
    elif r and (r[-1] & 0x80):
        r.append (0)
    return ''.join ([chr(x) for x in r])

def unrender_int (s):
    n = 0
    ls = len(s)
    neg = False
    for i in range (ls - 1, -1, -1):
        b = ord (s[i])
        n <<= 8
        if i == ls - 1 and b & 0x80:
            neg = True
            n |= b & 0x7f
        else:
            n |= b
    if neg:
        return -n
    else:
        return n

# I can't tell for sure, but it really looks like the operator<<(vch) in script.h
#  assumes little-endian?
def make_push_str (s):
    ls = len(s)
    if ls < OP_PUSHDATA1:
        return chr(ls) + s
    elif ls < 0xff:
        return chr(OP_PUSHDATA1) + chr(ls) + s
    elif ls < 0xffff:
        return chr(OP_PUSHDATA2) + struct.pack ("<H", ls) + s
    else:
        return chr(OP_PUSHDATA4) + struct.pack ("<L", ls) + s

def make_push_int (n):
    if n == 0:
        return chr(OP_0)
    elif n == 1:
        return chr(OP_1)
    elif n >= 2 and n <= 16:
        return chr(80 + n)
    else:
        return make_push_str (render_int (n))

class script_parser:
    def __init__ (self, script):
        self.s = script
        self.pos = 0
        self.length = len (script)

    def peek (self):
        return ord (self.s[self.pos])

    def next (self):
        result = ord (self.s[self.pos])
        self.pos += 1
        return result

    def get_str (self, n=1):
        result = self.s[self.pos:self.pos + n]
        self.pos += n
        if len(result) != n:
            raise ScriptUnderflow (self.pos)
        return result

    def get_int (self, count=4):
        bl = [self.next() for x in range (count)]
        n = 0
        for b in reversed (bl):
            n <<= 8
            n |= b
        return n

    def parse (self):
        code = []
        last_insn = None
        code_sep = None
        while self.pos < self.length:
            insn = self.next()
            if insn >= 0 and insn <= 75:
                code.append ((KIND_PUSH, self.get_str (insn)))
            elif insn == OP_PUSHDATA1:
                size = self.next()
                code.append ((KIND_PUSH, self.get_str (size)))
            elif insn == OP_PUSHDATA2:
                code.append ((KIND_PUSH, self.get_str (self.get_int (2))))
            elif insn == OP_PUSHDATA4:
                code.append ((KIND_PUSH, self.get_str (self.get_int (4))))
            elif insn in (OP_IF, OP_NOTIF):
                sub0, end0 = self.parse()
                sense = insn == OP_IF
                if end0 == OP_ELSE:
                    sub1, end1 = self.parse()
                    if end1 != OP_ENDIF:
                        raise BadScript (self.pos)
                    code.append ((KIND_COND, sense, sub0, sub1))
                elif end0 != OP_ENDIF:
                    raise BadScript (self.pos)
                else:
                    code.append ((KIND_COND, sense, sub0, None))
            elif insn in (OP_ELSE, OP_ENDIF):
                return code, insn
            elif insn == OP_CODESEPARATOR:
                code_sep = self.pos
            elif insn in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                #code.append ((KIND_CHECK, insn, self.s[code_sep:self.pos]))
                # XXX goes to the end of the script, not stopping at this position.
                code.append ((KIND_CHECK, insn, self.s[code_sep:]))
            elif insn in (OP_VERIF, OP_VERNOTIF):
                raise BadScript (self.pos)
            else:
                if insn in disabled:
                    raise DisabledError (self.pos)
                else:
                    #insn_name = opcode_map_rev.get (insn, insn)
                    code.append ((KIND_OP, insn))
            last_insn = insn
        return code, None

def pprint_script (p):
    r = []
    for insn in p:
        kind = insn[0]
        if kind == KIND_PUSH:
            _, data = insn
            if not data:
                r.append ('')
            else:
                r.append ('0x' + data.encode ('hex'))
        elif kind == KIND_COND:
            _, sense, sub0, sub1 = insn
            if sense:
                op = 'IF'
            else:
                op = 'NOTIF'
            r.append ([op] + pprint_script (sub0))
            if sub1:
                r.append (['ELSE'] + pprint_script (sub1))
        elif kind == KIND_CHECK:
            _, op, _ = insn
            r.append (opcode_map_rev[op])
        elif kind == KIND_OP:
            _, op = insn
            r.append (opcode_map_rev.get (op, 'OP_INVALID_%x' % (op,)))
    return r

def remove_codeseps (p):
    r = []
    for insn in p:
        if insn[0] == KIND_OP and insn[1] == 'OP_CODESEPARATOR':
            pass
        elif insn[0] == KIND_COND:
            _, sense, sub0, sub1 = insn
            sub0 = remove_codeseps (sub0)
            if sub1:
                sub1 = remove_codeseps (sub1)
            r.append ((KIND_COND, sense, sub0, sub1))
        else:
            r.append (insn)
    return r

def is_true (v):
    # check against the two forms of ZERO
    return v not in ('', '\x80')

lo32 = -(2 ** 31)
hi32 = (2 ** 31) - 1

def check_int (n):
    if not (lo32 <= n <= hi32):
        raise BadNumber
    return n

class machine:
    def __init__ (self):
        self.stack = []
        self.altstack = []

    def clear_alt (self):
        self.altstack = []

    def top (self):
        return self.stack[-1]

    def pop (self):
        return self.stack.pop()

    def push (self, item):
        self.stack.append (item)

    def push_int (self, n):
        self.stack.append (render_int (n))

    # the wiki says that numeric ops are limited to 32-bit integers,
    #  however at least one of the test cases (which try to enforce this)
    #  seem to violate this:
    # ["2147483647 DUP ADD", "4294967294 EQUAL", ">32 bit EQUAL is valid"],
    # by adding INT32_MAX to itself we overflow a signed 32-bit int.
    # NOTE: according to Gavin Andresen, only the input operands have this limitation,
    #   the output can overflow... a script quirk.

    def pop_int (self, check=True):
        n = unrender_int (self.pop())
        if check:
            check_int (n)
        return n

    def push_alt (self):
        self.altstack.append (self.pop())

    def pop_alt (self):
        self.push (self.altstack.pop())

    def need (self, n):
        if len(self.stack) < n:
            raise StackUnderflow

    def needalt (self, n):
        if len(self.altstack) < n:
            raise AltStackUnderflow

    def dump (self):
        W ('  alt=%r\n' % self.altstack,)
        W ('stack=%r\n' % self.stack,)

    def truth (self):
        return is_true (self.pop())

# machine with placeholders for things we need to perform tx verification

class verifying_machine (machine):

    def __init__ (self, prev_outscript, tx, index):
        machine.__init__ (self)
        self.prev_outscript = prev_outscript
        self.tx = tx
        self.index = index

    def check_sig (self, s):
        pub_key = self.pop()
        sig = self.pop()
        s0 = parse_script (s)
        s1 = remove_codeseps (s0)
        s2 = remove_sigs (s1, [sig])  # rare?
        s3 = unparse_script (s2)
        return self.check_one_sig (pub_key, sig, s3)

    def check_one_sig (self, pub, sig, s):
        sig, hash_type = sig[:-1], ord(sig[-1])
        if hash_type != 1:
            W ('hash_type=%d\n' % (hash_type,))
            raise NotImplementedError
        to_hash = self.tx.get_ecdsa_hash (self.index, s, hash_type)
        return self.tx.verify1 (pub, sig, to_hash)

    # having trouble understanding if there is a difference between: CHECKMULTISIG and P2SH.
    # https://en.bitcoin.it/wiki/BIP_0016
    def check_multi_sig (self, s):
        npub = self.pop_int()
        #print 'npub=', npub
        pubs = [self.pop() for x in range (npub)]
        nsig = self.pop_int()
        #print 'nsig=', nsig
        sigs = [self.pop() for x in range (nsig)]

        s0 = parse_script (s)
        s1 = remove_codeseps (s0)
        s2 = remove_sigs (s1, sigs)  # rare?
        s3 = unparse_script (s2)

        for sig in sigs:
            nmatch = 0
            #print 'checking sig...'
            for pub in pubs:
                if self.check_one_sig (pub, sig, s3):
                    nmatch += 1
            if nmatch == 0:
                #print 'sig matched no pubs'
                return 0
        return 1

def remove_sigs (p, sigs):
    "remove any of <sigs> from <p>"
    r = []
    for insn in p:
        kind = insn[0]
        if kind == KIND_PUSH and insn[1] in sigs:
            pass
        else:
            r.append (insn)
    return r

def do_equal (m):
    m.need(2)
    v0 = m.pop()
    v1 = m.pop()
    if v0 == v1:
        m.push_int (1)
    else:
        m.push_int (0)
def do_verify (m):
    m.need (1)
    if not m.truth():
        raise ScriptFailure
def do_equalverify (m):
    m.need (2)
    do_equal (m)
    do_verify (m)
def do_1negate (m):
    m.push_int (-1)
def do_nop (m):
    pass
def do_dup (m):
    m.need (1)
    m.push (m.top())
def do_toaltstack (m):
    m.need (1)
    m.push_alt()
def do_fromaltstack (m):
    m.needalt (1)
    m.pop_alt()
def do_drop (m):
    m.need (1)
    m.pop()
def do_ifdup (m):
    m.need (1)
    v = m.top()
    if is_true (v):
        m.push (v)
def do_depth (m):
    m.push_int (len (m.stack))
def do_nip (m):
    m.need (2)
    v = m.pop()
    m.pop()
    m.push (v)
def do_over (m):
    m.need (2)
    m.push (m.stack[-2])
def do_pick (m):
    m.need (1)
    n = 1 + m.pop_int()
    if n < 1:
        raise BadScript
    m.need (n)
    m.push (m.stack[-n])
def do_roll (m):
    m.need (1)
    n = 1 + m.pop_int()
    if n < 1:
        raise BadScript
    m.need (n)
    v = m.stack[-n]
    del m.stack[-n]
    m.push (v)
def do_rot (m):
    m.need (3)
    v = m.stack[-3]
    del m.stack[-3]
    m.push (v)
def do_swap (m):
    m.need (2)
    m.stack[-1], m.stack[-2] = m.stack[-2], m.stack[-1]
def do_tuck (m):
    m.need (2)
    m.stack.insert (-2, m.top())
def do_2drop (m):
    m.need (2)
    m.pop()
    m.pop()
def do_2dup (m):
    m.need (2)
    v0, v1 = m.stack[-2:]
    m.stack.extend ([v0, v1])
def do_3dup (m):
    m.need (3)
    v0, v1, v2 = m.stack[-3:]
    m.stack.extend ([v0, v1, v2])
def do_2over (m):
    m.need (4)
    v0, v1 = m.stack[-4:-2]
    m.stack.extend ([v0, v1])
def do_2rot (m):
    m.need (6)
    v0, v1 = m.stack[-6:-4]
    del m.stack[-6:-4]
    m.stack.extend ([v0, v1])
def do_2swap (m):
    m.need (4)
    v0, v1 = m.stack[-4:-2]
    del m.stack[-4:-2]
    m.stack.extend ([v0, v1])
def do_cat (m):
    v1 = m.pop()
    v0 = m.pop()
    m.push (v0 + v1)
def do_substr (m):
    m.need (3)
    n = m.pop_int()
    p = m.pop_int()
    s = m.pop()
    if not (n > 0 and n < len (s)):
        raise ScriptFailure
    if not (p >= 0 and p < (len(s) - 1)):
        raise ScriptFailure
    m.push (s[p:p + n])
def do_left (m):
    m.need (2)
    n = m.pop_int()
    s = m.pop()
    if n < 0 or n > (len(s) - 1):
        raise ScriptFailure
    m.push (s[0:n])
def do_right (m):
    m.need (2)
    n = m.pop_int()
    s = m.pop()
    if n < 0 or n > (len(s) - 1):
        raise ScriptFailure
    m.push (s[n:])
def do_size (m):
    m.need (1)
    m.push_int (len (m.top()))
def do_1add (m):
    m.need (1)
    m.push_int (1 + m.pop_int())
def do_1sub (m):
    m.need (1)
    m.push_int (m.pop_int() - 1)
def do_2mul (m):
    m.need (1)
    m.push_int (2 * m.pop_int())
def do_2div (m):
    m.need (1)
    m.push_int (m.pop_int() >> 1)
def do_negate (m):
    m.need (1)
    m.push_int (-m.pop_int())
def do_abs (m):
    m.push_int (abs (m.pop_int()))
def do_not (m):
    m.need (1)
    if m.truth():
        m.push_int (0)
    else:
        m.push_int (1)
def do_0notequal (m):
    if m.pop_int() == 0:
        m.push_int (0)
    else:
        m.push_int (1)
def do_add (m):
    m.need (2)
    m.push_int (m.pop_int() + m.pop_int())
def do_sub (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 - v1)
def do_mul (m):
    m.need (2)
    m.push_int (m.pop_int() * m.pop_int())
def do_div (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 // v1)
def do_mod (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 % v1)
def do_lshift (m):
    m.need (2)
    n = m.pop_int()
    v = m.pop_int()
    if n < 0 or n > 2048:
        raise ScriptFailure
    m.push_int (v << n)
def do_rshift (m):
    m.need (2)
    n = m.pop_int()
    v = m.pop_int()
    if n < 0 or n > 2048:
        raise ScriptFailure
    m.push_int (v >> n)
def do_booland (m):
    m.need (2)
    v0 = m.pop_int()
    v1 = m.pop_int()
    m.push_int (v0 and v1)
def do_boolor (m):
    m.need (2)
    v0 = m.pop_int()
    v1 = m.pop_int()
    m.push_int (v0 or v1)
def do_numequal (m):
    m.need (2)
    m.push_int (m.pop_int() == m.pop_int())
def do_numequalverify (m):
    do_numequal (m)
    do_verify (m)
def do_numnotequal (m):
    m.need (2)
    m.push_int (m.pop_int() != m.pop_int())
def do_lessthan (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 < v1)
def do_greaterthan (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 > v1)
def do_lessthanorequal (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 <= v1)
def do_greaterthanorequal (m):
    m.need (2)
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v0 >= v1)
def do_min (m):
    m.need (2)
    m.push_int (min (m.pop_int(), m.pop_int()))
def do_max (m):
    m.need (2)
    m.push_int (max (m.pop_int(), m.pop_int()))
def do_within (m):
    m.need (3)
    v2 = m.pop_int()
    v1 = m.pop_int()
    v0 = m.pop_int()
    m.push_int (v1 <= v0 < v2)
def do_ripemd160 (m):
    m.need (1)
    s = m.pop()
    h0 = hashlib.new ('ripemd160')
    h0.update (s)
    m.push (h0.digest())
def do_sha1 (m):
    m.need (1)
    s = m.pop()
    h0 = hashlib.new ('sha1')
    h0.update (s)
    m.push (h0.digest())
def do_sha256 (m):
    m.need (1)
    s = m.pop()
    h0 = hashlib.new ('sha256')
    h0.update (s)
    m.push (h0.digest())
def do_hash160 (m):
    m.need (1)
    s = m.pop()
    h0 = hashlib.new ('sha256')
    h0.update (s)
    h1 = hashlib.new ('ripemd160')
    h1.update (h0.digest())
    m.push (h1.digest())
def do_hash256 (m):
    m.need (1)
    s = m.pop()
    h0 = hashlib.new ('sha256')
    h0.update (s)
    h1 = hashlib.new ('sha256')
    h1.update (h0.digest())
    m.push (h1.digest())
def do_nop1 (m):
    pass
do_nop2 = do_nop1
do_nop3 = do_nop1
do_nop4 = do_nop1
do_nop5 = do_nop1
do_nop6 = do_nop1
do_nop7 = do_nop1
do_nop8 = do_nop1
do_nop9 = do_nop1
do_nop10 = do_nop1

# these will probably be done inline when the eval engine is moved into cython
def do_1 (m):
    m.push_int (1)
def do_2 (m):
    m.push_int (2)
def do_3 (m):
    m.push_int (3)
def do_4 (m):
    m.push_int (4)
def do_5 (m):
    m.push_int (5)
def do_6 (m):
    m.push_int (6)
def do_7 (m):
    m.push_int (7)
def do_8 (m):
    m.push_int (8)
def do_9 (m):
    m.push_int (9)
def do_10 (m):
    m.push_int (10)
def do_11 (m):
    m.push_int (11)
def do_12 (m):
    m.push_int (12)
def do_13 (m):
    m.push_int (13)
def do_14 (m):
    m.push_int (14)
def do_15 (m):
    m.push_int (15)
def do_16 (m):
    m.push_int (16)

# The disabled opcodes are in a test near the top of EvalScript in script.cpp.
# The unit tests require that these fail.
disabled = set ([
    OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR,
    OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
])

op_funs = {}
g = globals()
for name in g.keys():
    if name.startswith ('do_'):
        opname = ('op_%s' % (name[3:])).upper()
        code = opcode_map_fwd[opname]
        op_funs[code] = g[name]

from hashlib import sha256

def dhash (s):
    return sha256(sha256(s).digest()).digest()

def pinsn (insn):
    kind = insn[0]
    if kind == KIND_PUSH:
        print 'push %r' % (insn[1])
    elif kind == KIND_OP:
        _, op = insn
        print '%s' % (opcode_map_rev.get (op, str(op)))
    elif kind == KIND_COND:
        if insn[1]:
            print 'IF'
        else:
            print 'NOTIF'
    elif kind == KIND_CHECK:
        op = insn[1]
        print '%s' % (opcode_map_rev.get (op, str(op)))

def eval_script (m, s):
    for insn in s:
        #print '---------------'
        #m.dump()
        #pinsn (insn)
        kind = insn[0]
        if kind == KIND_PUSH:
            _, data = insn
            m.push (data)
        elif kind == KIND_OP:
            _, op = insn
            op_funs[op](m)
        elif kind == KIND_COND:
            _, sense, tcode, fcode = insn
            truth = m.truth()
            if (sense and truth) or (not sense and not truth):
                eval_script (m, tcode)
            elif fcode is not None:
                eval_script (m, fcode)
        elif kind == KIND_CHECK:
            _, op, s0 = insn
            if op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                result = m.check_sig (s0)
                if op == OP_CHECKSIGVERIFY:
                    do_verify (m)
                return result
            elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                result = m.check_multi_sig (s0)
                if op == OP_CHECKMULTISIGVERIFY:
                    do_verify (m)
                return result
            else:
                raise NotImplementedError
        else:
            raise ValueError ("unknown kind: %r" % (kind,))
    # notify the caller when the script does *not* end in a CHECKSIG operation.
    return None
