# -*- Mode: Python -*-

# parse the test cases from bitcoin-qt

import os
import json

from caesure.script import *
from caesure.bitcoin import TX, ZERO_NAME, KEY

def frob (s):
    # the test files are illegal json.  escape all the newlines in strings.
    state_string = False
    r = []
    for i in range (len (s)):
        ch = s[i]
        if state_string:
            if ch == '\n':
                ch = r'\u000a'
            elif ch == '"':
                state_string = False
            r.append (ch)
        else:
            if ch == '"':
                state_string = True
            r.append (ch)
    return ''.join (r)

where = '/Users/rushing/src/git/bitcoin/src/test/data/'

valid   = json.loads (frob (open (os.path.join (where, 'script_valid.json'), 'rb').read()))
invalid = json.loads (frob (open (os.path.join (where, 'script_invalid.json'), 'rb').read()))

import re
digits = re.compile ('-?[0-9]+$')

# heh, this is quite a challenge.  it's a little too rfc-822 for my taste, though.
def parse_test (s):
    r = []
    for e in s.split():
        if digits.match (e):
            # push this integer
            r.append (make_push_int (int (e)))
        elif e.startswith ('0x'):
            # what does this mean? "Raw hex data, inserted NOT pushed onto stack:"
            r.append (e[2:].decode ('hex'))
        elif len(e) >= 2 and e[0] == "'" and e[-1] == "'":
            # these actually are *pushed*, usually with PUSHDATA{1,2,4}
            r.append (make_push_str (e[1:-1]))
        elif opcode_map_fwd.has_key (e):
            r.append (chr(opcode_map_fwd[e]))
        elif opcode_map_fwd.has_key ('OP_'+e):
            r.append (chr(opcode_map_fwd['OP_'+e]))
        else:
            raise ValueError ("i'm so conFUSEd")
    return ''.join (r)

#class test_machine (verifying_machine_p2sh):
class test_machine (verifying_machine):

    def __init__ (self):
        machine.__init__ (self)
        self.debug = True
        self.index = 0
        self.KEY = KEY

    def eval_script (self, lock_script, unlock_script):
        self.tx = TX()
        self.tx.inputs = [((ZERO_NAME, 4294967295), '\x00\x00', 4294967295)]
        self.tx.outputs = [(0, unlock_script)]
        return verifying_machine.eval_script (self, lock_script, unlock_script)

import sys
W = sys.stderr.write

def do_one (lock_script, unlock_script):
    W (('-' *50)+'\n')
    m = test_machine()
    m.eval_script (lock_script, unlock_script)

def unit_tests():
    for v in valid:
        v = [bytes(x) for x in v]
        if len(v) >= 2:
            unlock = parse_test (v[0])
            lock = parse_test (v[1])
            print v
            print pprint_script (parse_script (unlock))
            print pprint_script (parse_script (lock))
            do_one (lock, unlock)
    if False:
        W ('--- SHOULD FAIL ---\n')
        for v in invalid:
            # XXX grok flags
            sig, pub, flags = v[:2]
            if len(v)>2:
                print v[2]
            try:
                do_one (sig, pub)
            except:
                print sys.exc_info()
            else:
                W ('DID NOT FAIL!\n')
                raw_input()

def pprint_unit_tests():
    for v in valid:
        sig, pub = v[:2]
        sig0 = parse_script (sig)
        pub0 = parse_script (pub)
        W ('%r\n%r\n' % (sig0, pub0))
        W ('%r\n%r\n' % (pprint_script (sig0), pprint_script (pub0)))
        W ('-----------\n')

if __name__ == '__main__':
    unit_tests()
    #pprint_unit_tests()
