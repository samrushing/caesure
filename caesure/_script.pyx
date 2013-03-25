# -*- Mode: Python -*-

import hashlib
import struct
from pprint import pprint as pp

from libc.stdint cimport uint64_t, int64_t, uint32_t, int32_t, uint16_t, int16_t, uint8_t

cdef extern from "opcodes.h":
    uint8_t OP_0, OP_FALSE, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    uint8_t OP_1NEGATE, OP_RESERVED, OP_1, OP_TRUE, OP_1, OP_2, OP_3, OP_4,
    uint8_t OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14,
    uint8_t OP_15, OP_16, OP_NOP, OP_VER, OP_IF, OP_NOTIF, OP_VERIF,
    uint8_t OP_VERNOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN,
    uint8_t OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP,
    uint8_t OP_2OVER, OP_2ROT, OP_2SWAP, OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP,
    uint8_t OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK,
    uint8_t OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_SIZE, OP_INVERT, OP_AND,
    uint8_t OP_OR, OP_XOR, OP_EQUAL, OP_EQUALVERIFY, OP_RESERVED1,
    uint8_t OP_RESERVED2, OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV, OP_NEGATE,
    uint8_t OP_ABS, OP_NOT, OP_0NOTEQUAL, OP_ADD, OP_SUB, OP_MUL, OP_DIV,
    uint8_t OP_MOD, OP_LSHIFT, OP_RSHIFT, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
    uint8_t OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
    uint8_t OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX,
    uint8_t OP_WITHIN, OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160,
    uint8_t OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    uint8_t OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_NOP1, OP_NOP2,
    uint8_t OP_NOP3, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9,
    uint8_t OP_NOP10, OP_SMALLINTEGER, OP_PUBKEYS, OP_PUBKEYHASH, OP_PUBKEY,
    uint8_t OP_INVALIDOPCODE

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

# I can't tell for sure, but it really looks like the operator<<(vch) in script.h
#  assumes little-endian?

# wow, cython makes this really hard...
cpdef bytes make_push_str (bytes s):
    cdef int ls = len(s)
    if ls < OP_PUSHDATA1:
        return chars[ls] + s
    elif ls < 0xff:
        # PUSHDATA1
        return c'\x4c' + chars[ls] + s
    elif ls < 0xffff:
        # PUSHDATA2
        return c'\x4d' + pack_u16(ls) + s
    else:
        # PUSHDATA4
        return c'\x4e' + pack_u32(ls) + s

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
class DisabledError (ScriptError):
    pass
class BadNumber (ScriptError):
    pass

cdef KIND_PUSH  = 0
cdef KIND_COND  = 1
cdef KIND_OP    = 2
cdef KIND_CHECK = 3

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
        if self.pos + n > self.length:
            raise ScriptUnderflow

    cdef uint8_t peek (self):
        self.need (1)
        return self.p[self.pos]

    cdef uint8_t next (self):
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

    cdef uint32_t get_int (self, uint32_t count):
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
                sub0 = self.parse (&end)
                sense = insn == OP_IF
                if end == OP_ELSE:
                    sub1 = self.parse (&end)
                    if end != OP_ENDIF:
                        raise BadScript (self.pos)
                    code.append ((KIND_COND, sense, sub0, sub1))
                elif end != OP_ENDIF:
                    raise BadScript (self.pos)
                else:
                    code.append ((KIND_COND, sense, sub0, None))
            elif insn in (OP_ELSE, OP_ENDIF):
                out_end[0] = insn
                return code
            elif insn == OP_CODESEPARATOR:
                code_sep = self.pos
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

def parse_script (s):
    cdef uint8_t end = 0
    code = script_parser(s).parse(&end)
    if end != 0:
        raise BadScript
    return code

cpdef bytes unparse_script (list p):
    cdef list r = []
    cdef uint8_t op
    for insn in p:
        kind = insn[0]
        if kind == KIND_PUSH:
            r.append (make_push_str (insn[1]))
        elif kind == KIND_COND:
            _, sense, sub0, sub1 = insn
            if sense:
                op = OP_IF
            else:
                op = OP_NOTIF
            r.append (chars[op])
            r.append (unparse_script (sub0))
            if sub1:
                r.append (chars[OP_ELSE])
                r.append (unparse_script (sub1))
            r.append (chars[OP_ENDIF])
        elif kind == KIND_CHECK:
            op = insn[1]
            r.append (chars[op])
        elif kind == KIND_OP:
            op = insn[1]
            r.append (chars[op])
    return ''.join (r)
