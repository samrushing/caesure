# -*- Mode: Python -*-

# parse the test cases from bitcoin-core

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

import re
digits = re.compile ('-?[0-9]+$')

def parse_test (s):
    r = []
    for e in s.split():
        if digits.match (e):
            # push this integer
            r.append (make_push_int (int (e)))
        elif e.startswith ('0x'):
            # add raw hex to the script
            r.append (e[2:].decode ('hex'))
        elif len(e) >= 2 and e[0] == "'" and e[-1] == "'":
            # add a push to the script
            r.append (make_push_str (e[1:-1]))
        elif opcode_map_fwd.has_key (e):
            r.append (chr(opcode_map_fwd[e]))
        elif opcode_map_fwd.has_key ('OP_'+e):
            r.append (chr(opcode_map_fwd['OP_'+e]))
        else:
            raise ValueError ("i'm so conFUSEd")
    return ''.join (r)

import sys
W = sys.stderr.write

def do_one (unlock_script, lock_script, flags):
    #W (('-' *50)+'\n')

    tx0 = TX()
    tx0.inputs = [((ZERO_NAME, 4294967295), '\x00\x00', 4294967295)]
    tx0.outputs = [(0, lock_script)]
    name = tx0.get_hash()
    tx1 = TX()
    tx1.inputs = [((name, 0), unlock_script, 4294967295)]
    tx1.outputs = [(0, '')]

    if 'P2SH' in flags:
        m = verifying_machine_p2sh (tx1, 0, KEY)
    else:
        m = verifying_machine (tx1, 0, KEY)
    m.strictenc = 'STRICTENC' in flags
    m.minimal = 'MINIMALDATA' in flags
    m.nulldummy = 'NULLDUMMY' in flags
    m.dersig = 'DERSIG' in flags
    m.low_s = 'LOW_S' in flags
    m.sigpushonly = 'SIGPUSHONLY' in flags
    m.eval_script (unlock_script, lock_script)

def dump_script (unlock, lock):
    u0 = parse_script (unlock)
    l0 = parse_script (lock)
    u1 = pprint_script (u0)
    l1 = pprint_script (l0)
    W ('bytes:\n')
    W ('  unlock: %s\n' % (unlock.encode('hex'),))
    W ('    lock: %s\n' % (lock.encode('hex'),))
    W ('parsed:\n')
    W ('  unlock: %r\n' % (u0,))
    W ('    lock: %r\n' % (l0,))
    W ('pprint:\n')
    W ('  unlock: %r\n' % (u1,))
    W ('    lock: %r\n' % (l1,))

def unit_tests():
    global verbose
    W ('%d valid tests...\n' % (len(valid),))
    fails = []
    for num, v in valid:
        v = [bytes(x) for x in v]
        if len(v) >= 2:
            flags = v[2].split(',')
            if verbose:
                W ('--- valid %d ---\n' % (num,))
                W ('json:\n')
                W ('  unlock: %r\n' % (v[0],))
                W ('    lock: %r\n' % (v[1],))
            unlock = parse_test (v[0])
            lock = parse_test (v[1])
            if verbose:
                dump_script (unlock, lock)
            try:
                do_one (unlock, lock, flags)
            except Exception as e:
                fails.append ((num, 'valid', v, e))
    W ('%d invalid tests...\n' % (len(invalid),))
    for num, v in invalid:
        v = [bytes(x) for x in v]
        if len(v) >= 2:
            flags = v[2].split(',')
            if verbose:
                W ('--- invalid %d ---\n' % (num,))
                W ('json:\n')
                W ('  unlock: %r\n' % (v[0],))
                W ('    lock: %r\n' % (v[1],))
            try:
                unlock = parse_test (v[0])
                lock = parse_test (v[1])
                if verbose:
                    dump_script (unlock, lock)
                do_one (unlock, lock, flags)
                fails.append ((num, 'invalid', v, None))
            except:
                pass
    if fails:
        W ('%d failures:\n' % (len(fails)))
        for i, kind, fail, why in fails:
            W ('  %d %s %r, %r\n' % (i, kind, fail, why))

def load_json_test_file (path):
    return list (enumerate (json.loads (frob (open (path, 'rb').read()))))

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser (description='run bitcoin-core unit script tests')
    p.add_argument ('-v', type=int, action='append', help='run a specific valid test by number')
    p.add_argument ('-i', type=int, action='append', help='run a specific invalid test by number')
    p.add_argument ('-d', action='store_true', help='debug')
    p.add_argument ('--verbose', action='store_true', help='dump each script test before execution')
    p.add_argument ('where', type=str, help='location of json test files', metavar='PATH')

    args = p.parse_args()
    verbose = args.verbose

    valid = load_json_test_file (os.path.join (args.where, 'script_valid.json'))
    invalid = load_json_test_file (os.path.join (args.where, 'script_invalid.json'))

    if args.v is not None:
        tests = []
        for num in args.v:
            tests.append (valid[num])
        valid = tests
        invalid = []

    if args.i is not None:
        tests = []
        for num in args.i:
            tests.append (invalid[num])
        invalid = tests
        valid = []

    if args.d:
        verifying_machine.debug = True

    unit_tests()
