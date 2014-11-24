# -*- Mode: Python -*-

import hashlib
import struct
from pprint import pprint as pp
import sys

from coro.asn1.ber import decode, SEQUENCE, INTEGER
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

PUSH_OP = 0 # OP_1NEGATE, OP_0, OP_1 .. OP_16
PUSH_N  = 1 # <5> "abcde"
PUSH_1  = 2 # "a"
PUSH_2  = 3 # 0x1234 ....
PUSH_4  = 4 # 0xdeadbeef "never used..."

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

def make_push_int (n):
    if n == 0:
        return chr(OP_0)
    elif n == 1:
        return chr(OP_1)
    elif n >= 2 and n <= 16:
        return chr(80 + n)
    elif n == -1:
        return chr(OP_1NEGATE)
    else:
        return make_push_str (render_int (n))

# this will recreate IF/ELSE/END ops as well.
def walk_script (s):
    for insn in s:
        if insn[0] == KIND_COND:
            _, sense, sub0, elses = insn
            if sense:
                yield KIND_OP, OP_IF
            else:
                yield KIND_OP, OP_NOTIF
            for x in walk_script (sub0):
                yield x
            for i in range (len (elses)):
                for x in walk_script (elses[i]):
                    yield x
                if i != len(elses)-1:
                    yield KIND_OP, OP_ELSE
            yield KIND_OP, OP_ENDIF
        else:
            yield insn

def pprint_script (p):
    r = []
    for insn in p:
        kind = insn[0]
        if kind == KIND_PUSH:
            _, data, push_kind = insn
            if not data:
                r.append ('')
            else:
                r.append ('0x' + data.encode ('hex'))
        elif kind == KIND_COND:
            _, sense, sub0, elses = insn
            if sense:
                op = 'IF'
            else:
                op = 'NOTIF'
            clause = [op] + pprint_script (sub0)
            for sub1 in elses:
                clause.extend (['ELSE'] + pprint_script (sub1))
            r.append (clause)
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

# "Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
#  The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
#  but results may overflow (and are valid as long as they are not used in a subsequent
#  numeric operation)."

# NOTE: this is NOT the range of a signed 32-bit integer.
#   One value (-0x80000000) has been lost on the low end.

lo32 = -(2 ** 31) + 1
hi32 = +(2 ** 31) - 1

def check_int (n):
    if not (lo32 <= n <= hi32):
        raise BadNumber
    return n

class machine:

    debug = False

    def __init__ (self):
        self.stack = []
        self.altstack = []

    def clear_alt (self):
        self.altstack = []

    def clear_stack (self):
        self.stack = []

    def top (self):
        return self.stack[-1]

    def pop (self):
        return self.stack.pop()

    def push (self, item):
        self.stack.append (item)

    def push_int (self, n):
        self.push (render_int (n))

    def pop_int (self):
        item = self.pop()
        n = unrender_int (item)
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
        if len(self.altstack):
            W ('  alt:\n')
            for item in self.altstack:
                W ('    %r\n' % (item.encode ('hex'),))                
        W ('  stack:\n')
        for item in self.stack:
            W ('    %r\n' % (item.encode ('hex'),))
            
    def truth (self):
        return is_true (self.top())

# XXX think carefully about how these may relate to _script.pyx:ScriptErrors.
class VerifyError (Exception):
    pass
class BadSignature (VerifyError):
    pass

# Note: I have tried to replace scriptPubKey & scriptSig with lock_script & unlock_script respectively.
#  IMHO this is much less confusing, and is in line with the language used in Andreas' book.
#  [I previously used 'redeem' for 'unlock'].

# machine with placeholders for things we need to perform tx verification

class verifying_machine (machine):

    # various verification-level flags. mostly bip62.
    strictenc   = False
    low_s       = False
    minimal     = False
    nulldummy   = False
    dersig      = False
    sigpushonly = False

    def __init__ (self, tx, index, KEY):
        machine.__init__ (self)
        self.tx = tx
        self.index = index
        self.KEY = KEY

    def pop_int (self):
        # XXX bip62 requires that integer ops be represented minimally.
        item = self.top()
        n = machine.pop_int (self)
        if self.minimal:
            check_minimal_int (item, n)
        return n

    def verify_sig (self, pub_key, sig, data, already):
        k = self.KEY()
        k.set_pubkey (pub_key)
        r = k.verify (data, sig, already)
        if r == -1:
            # bogus signatures
            r  = 0
        assert (r in (0, 1))
        return r

    # Hugely Helpful: http://forum.bitcoin.org/index.php?topic=2957.20

    def get_tx_for_hash (self, tx0, index, sub_script, hash_type):
        tx1 = tx0.copy()
        for i, (outpoint, script, sequence)  in enumerate (tx1.inputs):
            if i == index:
                script = sub_script
            else:
                script = ''
            tx1.inputs[i] = outpoint, script, sequence
        hash_type0 = hash_type & 0x1f
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
                #raise BadScript ("SIGHASH_SINGLE: not enough outputs")
                return True, '\x01' + ('\x00' * 31) # really?
            tx1.outputs = tx1.outputs[:index+1]
            for i in range (index):
                tx1.outputs[i] = 0xffffffffffffffff, ''
            for i, (output, script, sequence) in enumerate (tx1.inputs):
                if i != index:
                    tx1.inputs[i] = output, script, 0
        else:
            # XXX looking at peter todd's version of python-bitcoinlib,
            #   it appears that any value here that is *not* NONE or SINGLE
            #   implies ALL?
            #raise BadScript ('hash_type: 0x%x' % (hash_type0,))
            pass
        if hash_type & SIGHASH_ANYONECANPAY:
            tx1.inputs = [tx1.inputs[index]]
        return False, tx1.render() + struct.pack ('<I', hash_type)

    def check_sig (self, s):
        pub_key = self.pop()
        sig = self.pop()
        s0 = parse_script (s)
        s1 = remove_codeseps (s0)
        s2 = remove_sigs (s1, [sig])
        s3 = unparse_script (s2, False)
        return self.check_one_sig (pub_key, sig, s3)

    valid_hashtypes = {
        0x01, 0x02, 0x03,
        0x81, 0x82, 0x83
        }

    def check_hashtype (self, hashtype):
        if hashtype not in self.valid_hashtypes:
            raise BadHashType (hashtype)

    def strict_pub (self, pub0):
        if pub0[0] not in '\x02\x03\x04':
            return 0
        elif pub0[0] == '\x04' and len(pub0) != 65:
            return 0
        elif len(pub0) != 33:
            return 0
        else:
            return 1

    def check_pub (self, pub):
        if not self.strict_pub (pub):
            raise BadDER (pub)

    def check_dersig (self, sig0):
        sig1, size = decode (sig0)
        if size != len(sig0):
            raise BadDER (sig0)
        elif not (len(sig1) == 2 and type(sig1[0]) is long and type(sig1[1]) is long):
            raise BadDER (sig0)
        else:
            [r, s] = sig1
            if SEQUENCE (INTEGER (r), INTEGER (s)) != sig0:
                raise BadDER (sig0)
            elif self.low_s and not (1 <= s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0):
                raise BadDER (sig0)
            elif not (1 <= r <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140):
                raise BadDER (sig0)

    def check_der (self, sig, pub, hashtype):
        if self.dersig or self.strictenc:
            self.check_dersig (sig)
        if self.strictenc:
            self.check_hashtype (hashtype)
            return self.strict_pub (pub)
        else:
            return 1

    def check_one_sig (self, pub, sig, s):
        if not sig:
            # XXX check for canonical form here?
            return 0
        else:
            sig, hash_type = sig[:-1], ord(sig[-1])
            # XXX I think these may *all* be check_xxx, not strict_xxx (i.e., they raise an error).
            if not self.check_der (sig, pub, hash_type):
                return 0
            else:
                #W ('hash_type=0x%x\n' % (hash_type,))
                already_hashed, data = self.get_tx_for_hash (self.tx, self.index, s, hash_type)
                #W ('data = %s\n' % (data.encode ("hex")))
                return self.verify_sig (pub, sig, data, already_hashed)

    def check_multi_sig (self, s):
        npub = self.pop_int()
        if npub < 0 or npub > 20:
            raise BadScript (s)
        pubs = [self.pop() for x in range (npub)]
        nsig = self.pop_int()
        if nsig < 0 or nsig > npub:
            raise BadScript (s)
        sigs = [self.pop() for x in range (nsig)]

        # forever broken?
        dummy = self.pop()
        if self.nulldummy and dummy != '':
            raise NonNullDummy (s)

        pubs = pubs[::-1]
        sigs = sigs[::-1]

        # XXX test for re-use of sig
        s0 = parse_script (s)
        s1 = remove_codeseps (s0)
        s2 = remove_sigs (s1, sigs)  # rare?
        s3 = unparse_script (s2, False)

        for sig in sigs:
            nmatch = 0
            matched = False
            for pub in pubs:
                if self.strictenc and not self.strict_pub (pub):
                    continue
                if self.check_one_sig (pub, sig, s3):
                    matched = True
                    break
            if not matched:
                return 0
        return 1

    def check_script0 (self, s):
        # checks on an unparsed script
        if len(s) > 10000:
            raise BadScript (s)

    # where should this magic number come from?
    push_max = 520

    def check_script1 (self, s):
        # make various checks on a parsed script
        op_count = 0
        last = None, None
        for insn in walk_script (s):
            if insn[0] == KIND_OP:
                if insn[1] in disabled:
                    raise BadScript (insn)
                if insn[1] != OP_RESERVED:
                    op_count += 1
            elif insn[0] == KIND_PUSH:
                #op_count += 1
                if len(insn[1]) > self.push_max:
                    raise BadScript (insn)
            elif insn[0] == KIND_CHECK:
                op_count += 1
                if insn[1] in (OP_CHECKMULTISIGVERIFY, OP_CHECKMULTISIG):
                    if last[0] == KIND_PUSH:
                        n = unrender_int (last[1])
                        if 0 <= n <= 20:
                            op_count += n
                        else:
                            op_count += 20
                    else:
                        op_count += 20
            if op_count > 201:
                raise BadScript (insn)
            last = insn

    def check_sigpushonly (self, sig):
        for insn in sig:
            if insn[0] != KIND_PUSH:
                raise BadScript (insn)

    def eval_script (self, unlock_script0, lock_script0):
        self.check_script0 (unlock_script0)
        self.check_script0 (lock_script0)
        unlock_script1 = parse_script (unlock_script0)
        lock_script1 = parse_script (lock_script0)
        if self.sigpushonly:
            self.check_sigpushonly (unlock_script1)
        self._eval_script (unlock_script1) # aka scriptSig
        self.clear_alt()
        self._eval_script (lock_script1)   # aka scriptPubKey
        do_verify (self)

    def _eval_script (self, s):
        self.check_script1 (s)
        for insn in s:
            if self.debug:
                W ('---------------\n')
                self.dump()
                pinsn (insn)
            kind = insn[0]
            if kind == KIND_PUSH:
                _, data, push_kind = insn
                if self.minimal:
                    check_minimal_push (data, push_kind)
                self.push (data)
            elif kind == KIND_OP:
                _, op = insn
                get_op_fun(op)(self)
            elif kind == KIND_COND:
                _, sense, tcode, elses = insn
                truth = self.truth()
                self.pop()
                if (sense and truth) or (not sense and not truth):
                    self._eval_script (tcode)
                    did = True
                else:
                    did = False
                for ecode in elses:
                    if not did:
                        self._eval_script (ecode)
                        did = True
                    else:
                        did = False
            elif kind == KIND_CHECK:
                _, op, s0 = insn
                if op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                    self.push_int (self.check_sig (s0) == 1)
                    if op == OP_CHECKSIGVERIFY:
                        do_verify (self)
                elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                    self.push_int (self.check_multi_sig (s0) == 1)
                    if op == OP_CHECKMULTISIGVERIFY:
                        do_verify (self)
                else:
                    raise NotImplementedError
            elif kind == KIND_SEP:
                pass
            else:
                raise ValueError ("unknown kind: %r" % (kind,))
            if len(self.stack) + len(self.altstack) > 1000:
                raise StackOverflow
        if self.debug:
            W ('---------------\n')
            self.dump()

class verifying_machine_p2sh (verifying_machine):

    def check_p2sh (self, lock_script, unlock_script):
        for insn in unlock_script:
            if insn[0] is not KIND_PUSH:
                raise BadScript (insn)

    def eval_script (self, unlock_script0, lock_script0):
        # special treatment here, the top item on the stack is a *script*,
        #   which must match the hash in <s>.  We then evaluate that script.
        #   there are additional requirements on the unlock script that will
        #   need to be checked...
        self.check_script0 (lock_script0)
        self.check_script0 (unlock_script0)
        lock_script = parse_script (lock_script0)
        unlock_script = parse_script (unlock_script0)
        #W ('lock_script = %r\n' % (lock_script))
        #W ('unlock_script = %r\n' % (unlock_script))
        if is_p2sh (lock_script):
            self.check_p2sh (lock_script, unlock_script)
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
                if self.debug:
                    W ('p2sh unlock_script: %s\n' % (pprint_script (unlock_script),))
                self._eval_script (unlock_script)
                do_verify (self)
        else:
            # XXX NOTE: this results in extra calls to check_script0
            verifying_machine.eval_script (self, unlock_script0, lock_script0)

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
    if m.pop() == m.pop():
        m.push_int (1)
    else:
        m.push_int (0)
def do_verify (m):
    m.need (1)
    if not m.truth():
        raise ScriptFailure
    else:
        m.pop()
def do_equalverify (m):
    m.need (2)
    do_equal (m)
    do_verify (m)
def do_return (m):
    raise ScriptFailure
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
    v = m.pop_int()
    if v == 0:
        m.push_int (1)
    else:
        m.push_int (0)
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
        if code not in disabled:
            op_funs[code] = g[name]

def get_op_fun (opcode):
    try:
        return op_funs[opcode]
    except KeyError:
        raise ScriptFailure

def pinsn (insn):
    kind = insn[0]
    if kind == KIND_PUSH:
        W ('push %r\n' % (insn[1].encode ('hex'),))
    elif kind == KIND_OP:
        _, op = insn
        W  ('%s\n' % (opcode_map_rev.get (op, str(op)),))
    elif kind == KIND_COND:
        if insn[1]:
            W ('IF\n')
        else:
            W ('NOTIF\n')
    elif kind == KIND_CHECK:
        op = insn[1]
        W ('%s\n' % (opcode_map_rev.get (op, str(op)),))
    elif kind == KIND_SEP:
        W ('OP_CODESEPARATOR\n')
    else:
        raise ValueError

