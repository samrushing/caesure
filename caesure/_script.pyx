# -*- Mode: Cython; indent-tabs-mode: nil -*-

import hashlib
import struct
from pprint import pprint as pp

from libc.stdint cimport uint64_t, int64_t, uint32_t, int32_t, uint16_t, int16_t, uint8_t

ctypedef enum:
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

cpdef bytes render_int (int64_t n):
    cdef bint neg
    cdef int i
    cdef unsigned char r[9]
    if n < 0:
        neg = True
        n = -n
    else:
        neg = False
    i = 0
    while n:
        r[i] = n & 0xff
        n >>= 8
        i += 1
    if neg:
        if r[i-1] & 0x80:
            r[i] = 0x80
            i += 1
        else:
            r[i-1] |= 0x80
    elif i and r[i-1] & 0x80:
        r[i] = 0x00
        i += 1
    return r[0:i]

cpdef int64_t unrender_int (bytes s):
    cdef unsigned char * p = s
    cdef int64_t n = 0
    cdef int ls = len (s)
    cdef int i
    cdef bint neg = False
    cdef unsigned char b
    for i in range (ls-1, -1, -1):
        b = p[i]
        n <<= 8
        if i == ls-1 and b & 0x80:
            neg = True
            n |= b & 0x7f
        else:
            n |= b
    if neg:
        return -n
    else:
        return n
        
cpdef check_minimal_int (bytes s0, int64_t n):
    cdef bytes s1 = render_int (n)
    if s0 != s1:
        raise NonMinimalInt (s0)

cpdef bytes pack_u16 (uint16_t n):
    return chr(n & 0xff) + chr ((n>>8) &0xff)

cpdef bytes pack_u32 (uint32_t n):
    cdef int i
    cdef char r[4]
    for i in range (4):
        r[i] = n & 0xff
        n >>= 8
    return r[:4]

cdef list chars = [0]*256
for i in range (256):
    chars[i] = chr(i)

cpdef bytes make_push_str (bytes s):
    # make a minimal (bip62) push.
    cdef int ls = len(s)
    if ls == 0:
        return chars[OP_0]
    elif ls == 1:
        d = ord(s[0])
        if 0x01 <= d <= 0x10:
            return chars[OP_1 + (d-1)]
        elif d == 0x81:
            return chars[OP_1NEGATE]
        else:
            return chars[ls] + s
    elif ls <= 75:
        return chars[ls] + s
    elif ls < 0xff:
        # PUSHDATA1
        return b'\x4c' + chars[ls] + s
    elif ls < 0xffff:
        # PUSHDATA2
        return b'\x4d' + pack_u16(ls) + s
    else:
        # PUSHDATA4
        return b'\x4e' + pack_u32(ls) + s

class ScriptError (Exception):
    pass
class ScriptFailure (ScriptError):
    pass
class BadScript (ScriptError):
    pass
class ScriptUnderflow (ScriptError):
    pass
class StackUnderflow (ScriptError):
    pass
class AltStackUnderflow (ScriptError):
    pass
class StackOverflow (ScriptError):
    pass
class DisabledError (ScriptError):
    pass
class BadNumber (ScriptError):
    pass
class StrictEncodingError (ScriptError):
    pass
class NonMinimalPush (StrictEncodingError):
    pass
class NonMinimalInt (StrictEncodingError):
    pass
class NonNullDummy (StrictEncodingError):
    pass
class BadDER (StrictEncodingError):
    pass
class BadHashType (StrictEncodingError):
    pass

cdef enum OP_KIND:
    KIND_PUSH  = 0,
    KIND_COND  = 1,
    KIND_OP    = 2,
    KIND_CHECK = 3,
    KIND_SEP   = 4,

cdef enum PUSH_KIND:
    PUSH_OP = 0 # OP_1NEGATE, OP_0, OP_1 .. OP_16
    PUSH_N  = 1 # <5> "abcde"
    PUSH_1  = 2 # "a"
    PUSH_2  = 3 # 0x1234 ....
    PUSH_4  = 4 # 0xdeadbeef "never used..."

cdef uint8_t disabled[255]
disabled_set = {
    OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR,
    OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
    }
for i in range (256):
    disabled[i] = 0
for i in disabled_set:
    disabled[i] = 1

cdef class script_parser:
    cdef bytes s
    cdef unsigned char * p
    cdef uint32_t pos
    cdef uint32_t length
    def __init__ (self, bytes script):
        self.s = script
        self.p = script
        self.pos = 0
        self.length = len (script)

    cdef need (self, uint32_t n):
        if n > self.length:
            raise ScriptUnderflow
        elif self.pos + n > self.length:
            raise ScriptUnderflow

    cdef uint8_t peek (self) except? -1:
        self.need (1)
        return self.p[self.pos]

    cdef uint8_t next (self) except? -1:
        cdef uint8_t r
        self.need (1)
        r = self.p[self.pos]
        self.pos += 1
        return r

    cdef bytes get_str (self, uint32_t n):
        cdef bytes result
        self.need (n)
        result = self.p[self.pos:self.pos+n]
        self.pos += n
        return result

    cdef uint32_t get_int (self, uint32_t count) except? -1:
        cdef uint32_t n = 0
        cdef int i
        cdef uint8_t b
        self.need (count)
        for i in range (count-1, -1, -1):
            b = self.p[self.pos+i]
            n <<= 8
            n |= b
        self.pos += count
        return n

    cdef list parse (self, uint8_t * out_end):
        cdef list code = []
        cdef uint32_t code_sep = 0
        cdef uint8_t insn
        cdef uint8_t end = 0
        cdef bytes data
        while self.pos < self.length:
            insn = self.next()
            if insn == 0:
                code.append ((KIND_PUSH, b'', PUSH_OP))
            elif insn == OP_1NEGATE:
                code.append ((KIND_PUSH, b'\x81', PUSH_OP))
            elif OP_1 <= insn <= OP_16:
                code.append ((KIND_PUSH, chars[(insn-OP_1)+1], PUSH_OP))
            elif insn >= 1 and insn <= 0x4b:
                code.append ((KIND_PUSH, self.get_str (insn), PUSH_N))
            elif insn == OP_PUSHDATA1:
                size = self.next()
                data = self.get_str (size)
                code.append ((KIND_PUSH, data, PUSH_1))
            elif insn == OP_PUSHDATA2:
                data = self.get_str (self.get_int (2))
                code.append ((KIND_PUSH, data, PUSH_2))
            elif insn == OP_PUSHDATA4:
                data = self.get_str (self.get_int (4))
                code.append ((KIND_PUSH, data, PUSH_4))
            elif insn in (OP_IF, OP_NOTIF):
                sub0 = self.parse (&end)
                sense = insn == OP_IF
                elses = []
                while end == OP_ELSE and self.pos < self.length:
                    sub1 = self.parse (&end)
                    elses.append (sub1)
                if end != OP_ENDIF:
                    raise BadScript (self.pos)
                else:
                    code.append ((KIND_COND, sense, sub0, elses))
            elif insn in (OP_ELSE, OP_ENDIF):
                out_end[0] = insn
                return code
            elif insn == OP_CODESEPARATOR:
                code_sep = self.pos
                code.append ((KIND_SEP,))
            elif insn in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                code.append ((KIND_CHECK, insn, self.s[code_sep:]))
            elif insn in (OP_VERIF, OP_VERNOTIF):
                raise BadScript (self.pos)
            else:
                if insn in disabled:
                    raise DisabledError (self.pos)
                else:
                    code.append ((KIND_OP, insn))
        return code

# XXX this is a temporary measure until I get the time to write a full matching engine.
def is_p2sh (list s):
    return (
        len(s) == 3
        and s[0] == (KIND_OP, OP_HASH160)
        and s[2] == (KIND_OP, OP_EQUAL)
        and len(s[1]) == 3
        and s[1][0] == KIND_PUSH
        and len(s[1][1]) == 20
        and s[1][2] == PUSH_N
        )

def is_unspendable (s):
    return (len(s) >= 1 and s[0] == (KIND_OP, OP_RETURN))

def parse_script (s):
    cdef uint8_t end = 0
    code = script_parser(s).parse(&end)
    if end != 0:
        raise BadScript
    return code

# my kingdom for pattern matching!
# most of this complexity is to accommodate bip62

cpdef bint is_minimal (bytes data, int push_kind):
    cdef uint8_t d
    cdef int ld = len(data)
    if ld == 0:
        return push_kind == PUSH_OP
    elif ld == 1:
        d = ord(data[0])
        if 0x01 <= d <= 0x10:
            return push_kind == PUSH_OP
        elif d == 0x81:
            return push_kind == PUSH_OP
        else:
            return push_kind == PUSH_N
    elif ld <= 75:
        return push_kind == PUSH_N
    elif ld <= 255:
        return push_kind == PUSH_1
    elif ld <= 520:
        return push_kind == PUSH_2
    else:
        return 1

cpdef check_minimal_push (bytes data, int push_kind):
    if not is_minimal (data, push_kind):
        raise NonMinimalPush ((data, push_kind))

cpdef unparse_push (list result, int push_kind, bytes data, bint minimal):
    cdef uint8_t op
    cdef int ld = len(data)
    cdef uint8_t d
    if minimal:
        # unparse to a minimal (bip62) push.
        # note that this clause does not examine <push_kind>.
        if ld == 0:
            result.append (chars[OP_0])
        elif ld == 1:
            d = ord(data[0])
            if 0x01 <= d <= 0x10:
                result.append (chars[OP_1 + (d-1)])
            elif d == 0x81:
                result.append (chars[OP_1NEGATE])
            else:
                result.append (make_push_str (data))
        else:
            result.append (make_push_str (data))
    else:
        # unparse to a (possibly non-minimal) push.
        if push_kind == PUSH_OP:
            if ld == 0:
                result.append (chars[OP_0])
            elif ld == 1:
                d = ord(data[0])
                if 0x01 <= d <= 0x10:
                    result.append (chars[OP_1 + (d-1)])
                elif d == 0x81:
                    result.append (chars[OP_1NEGATE])
                else:
                    raise ValueError ("bad PUSH_OP data")
            else:
                raise ValueError ("bad PUSH_OP data")
        elif push_kind == PUSH_N:
            if 1 <= ld <= 0x4b:
                result.extend ([chars[ld], data])
            else:
                raise ValueError ("bad PUSH_N data")
        elif push_kind == PUSH_1:
            if ld <= 1:
                result.extend ([chars[OP_PUSHDATA1], chars[ld], data])
            else:
                raise ValueError ("bad PUSH_1 data")
        elif push_kind == PUSH_2:
            if ld < 0xffff:
                result.extend ([chars[OP_PUSHDATA2], pack_u16 (ld), data])
            else:
                raise ValueError ("bad PUSH_2 data")
        elif push_kind == PUSH_4:
            raise ValueError ("illegal PUSH_4")
        else:
            raise ValueError ("bad push_kind")

cpdef bytes unparse_script (list p, bint minimal):
    cdef list r = []
    cdef uint8_t op
    cdef bytes data
    cdef uint8_t d
    cdef int push_kind
    for insn in p:
        kind = insn[0]
        if kind == KIND_PUSH:
            _, data, push_kind = insn
            unparse_push (r, push_kind, data, minimal)
        elif kind == KIND_COND:
            _, sense, sub0, elses = insn
            if sense:
                op = OP_IF
            else:
                op = OP_NOTIF
            r.append (chars[op])
            r.append (unparse_script (sub0, minimal))
            for sub1 in elses:
                r.append (chars[OP_ELSE])
                r.append (unparse_script (sub1, minimal))
            r.append (chars[OP_ENDIF])
        elif kind == KIND_CHECK:
            op = insn[1]
            r.append (chars[op])
        elif kind == KIND_OP:
            op = insn[1]
            r.append (chars[op])
        elif kind == KIND_SEP:
            r.append (chars[OP_CODESEPARATOR])
    return b''.join (r)
