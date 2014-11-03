# -*- Mode: Python -*-

import hashlib
import struct
from pprint import pprint as pp
import sys

from caesure._script import *

sha256 = hashlib.sha256

def dhash (s):
    return sha256(sha256(s).digest()).digest()

def rhash (s):
    h1 = hashlib.new ('ripemd160')
    h1.update (sha256(s).digest())
    return h1.digest()

W = sys.stderr.write

# XXX find some way to have these defined in _script.pyx
KIND_PUSH  = 0
KIND_COND  = 1
KIND_OP    = 2
KIND_CHECK = 3
KIND_SEP   = 4

SIGHASH_ALL          = 0x01
SIGHASH_NONE         = 0x02
SIGHASH_SINGLE       = 0x03
SIGHASH_ANYONECANPAY = 0x80

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
        elif kind == KIND_SEP:
            r.append ('OP_CODESEPARATOR')
    return r

def remove_codeseps (p):
    r = []
    for insn in p:
        if insn[0] == KIND_SEP:
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
        W ('  alt=%r\n' % [x.encode('hex') for x in self.altstack],)
        W ('stack=%r\n' % [x.encode('hex') for x in self.stack],)

    def truth (self):
        return is_true (self.pop())

# machine with placeholders for things we need to perform tx verification

class verifying_machine (machine):

    def __init__ (self, tx, index, KEY):
        machine.__init__ (self)
        self.tx = tx
        self.index = index
        self.KEY = KEY

    def verify_sig (self, pub_key, sig, to_hash):
        k = self.KEY()
        k.set_pubkey (pub_key)
        return k.verify (to_hash, sig)

    # Hugely Helpful: http://forum.bitcoin.org/index.php?topic=2957.20

    def get_ecdsa_hash (self, tx0, index, sub_script, hash_type):
        tx1 = tx0.copy()
        for i, (outpoint, script, sequence)  in enumerate (tx1.inputs):
            if i == index:
                script = sub_script
            else:
                script = ''
            tx1.inputs[i] = outpoint, script, sequence
        hash_type0 = hash_type & 0x31
        if hash_type0 == SIGHASH_ALL or hash_type0 == 0:
            # "no special further handling occurs"
            pass
        elif hash_type0 == SIGHASH_NONE:
            tx1.outputs = []
            for i, (output, script, sequence) in enumerate (tx1.inputs):
                if i != index:
                    tx1.inputs[i] = output, script, 0
        elif hash_type0 == SIGHASH_SINGLE:
            if index >= len(tx1.outputs):
                raise BadScript
            tx1.outputs = tx1.outputs[:index+1]
            for i in range (index):
                tx1.outputs[i] = 0xffffffffffffffff, ''
            for i, (output, script, sequence) in enumerate (tx1.inputs):
                if i != index:
                    tx1.inputs[i] = output, script, 0
        else:
            raise BadScript
        if hash_type & SIGHASH_ANYONECANPAY:
            tx1.inputs = [tx1.inputs[index]]
        return tx1.render() + struct.pack ('<I', hash_type)

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
        to_hash = self.get_ecdsa_hash (self.tx, self.index, s, hash_type)
        #W ('to_hash = %s\n' % (to_hash.encode ("hex")))
        return self.verify_sig (pub, sig, to_hash)

    def check_multi_sig (self, s):
        npub = self.pop_int()
        #print 'npub=', npub
        pubs = [self.pop() for x in range (npub)]
        nsig = self.pop_int()
        #print 'nsig=', nsig
        sigs = [self.pop() for x in range (nsig)]

        pubs = pubs[::-1]
        sigs = sigs[::-1]

        # XXX test for re-use of sig
        s0 = parse_script (s)
        s1 = remove_codeseps (s0)
        s2 = remove_sigs (s1, sigs)  # rare?
        s3 = unparse_script (s2)

        for sig in sigs:
            nmatch = 0
            matched = False
            #print 'checking sig...'
            for pub in pubs:
                if self.check_one_sig (pub, sig, s3):
                    matched = True
                    break
            if not matched:
                #print 'sig matched no pubs'
                return 0
        return 1

    def eval_script (self, lock_script, unlock_script):
        lock_script = parse_script (lock_script)
        unlock_script = parse_script (unlock_script)
        self._eval_script (unlock_script)
        self.clear_alt()
        return self._eval_script (lock_script)

    def _eval_script (self, s):
        for insn in s:
            #print '---------------'
            #self.dump()
            #pinsn (insn)
            kind = insn[0]
            if kind == KIND_PUSH:
                _, data = insn
                self.push (data)
            elif kind == KIND_OP:
                _, op = insn
                get_op_fun(op)(self)
            elif kind == KIND_COND:
                _, sense, tcode, fcode = insn
                truth = self.truth()
                if (sense and truth) or (not sense and not truth):
                    self._eval_script (tcode)
                elif fcode is not None:
                    self._eval_script (fcode)
            elif kind == KIND_CHECK:
                _, op, s0 = insn
                if op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                    result = self.check_sig (s0)
                    if op == OP_CHECKSIGVERIFY:
                        do_verify (self)
                    else:
                        self.push_int (int(result == 1))
                    return result
                elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                    result = self.check_multi_sig (s0)
                    if op == OP_CHECKMULTISIGVERIFY:
                        do_verify (self)
                    else:
                        self.push_int (int(result == 1))
                    return result
                else:
                    raise NotImplementedError
            elif kind == KIND_SEP:
                pass
            else:
                raise ValueError ("unknown kind: %r" % (kind,))
        #print '---------------'
        #self.dump()
        # notify the caller when the script does *not* end in a CHECKSIG operation.
        return None

class verifying_machine_p2sh (verifying_machine):

    def eval_script (self, lock_script, unlock_script):
        # special treatment here, the top item on the stack is a *script*,
        #   which must match the hash in <s>.  We then evaluate that script.
        #   there are additional requirements on the unlock script that will
        #   need to be checked...
        lock_script = parse_script (lock_script)
        unlock_script = parse_script (unlock_script)
        #W ('lock_script = %r\n' % (lock_script))
        #W ('unlock_script = %r\n' % (unlock_script))
        if is_p2sh (lock_script):
            if unlock_script[-1][0] != KIND_PUSH:
                #W ('p2sh: last item not a push\n')
                raise ScriptFailure
            elif rhash (unlock_script[-1][1]) != lock_script[1][1]:
                #W ('rhash failed\n')
                raise ScriptFailure
            else:
                p2sh_script = parse_script (unlock_script[-1][1])
                #W ('p2sh_script=%s\n' % (pprint_script (p2sh_script),))
                unlock_script = unlock_script[:-1] + p2sh_script
                #W ('unlock_script=%s\n' % (pprint_script (unlock_script),))
                return self._eval_script (unlock_script)
        else:
            self._eval_script (unlock_script)
            self.clear_alt()
            return self._eval_script (lock_script)


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

def get_op_fun (opcode):
    try:
        return op_funs[opcode]
    except KeyError:
        raise ScriptFailure

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
    elif kind == KIND_SEP:
        print 'OP_CODESEPARATOR'

