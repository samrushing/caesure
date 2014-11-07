# -*- Mode: Python; indent-tabs-mode: nil -*-

import coro
from caesure.bitcoin import KEY, TX
from caesure.script import *

import sys

W = sys.stderr.write

# XXX consider piping via stdin
# $ lpython ../utils/find_multi.py 315000 316000 > multisig_tests.txt
# $ lpython test_txns.py multisig_tests.txt

def HD (s):
    return s.decode ('hex')

# XXX fuzz these guys up and force them to fail.
def test (lock_script, tx_raw, index, block_timestamp):
    tx = TX()
    tx.unpack (tx_raw)
    tx.verify (index, lock_script, block_timestamp)
    
class BadFile:
    def __init__ (self, path):
        self.bad_path = path + '.bad'
        self.file = None
    def write (self, line):
        if self.file is None:
            self.file = open (self.bad_path, 'wb')
        self.file.write (line)
        self.file.flush()
    def close (self):
        if self.file:
            self.file.close()

def test_all (args):

    if args.debug:
        verifying_machine.debug = True

    good = 0
    bad  = 0
    
    fbad = BadFile (args.file)
    for line in open (args.file, 'rb'):
        if line.startswith ('#'):
            continue
        lock_script, txraw, index, block_timestamp = line.split()
        lock_script = HD (lock_script)
        txraw = HD (txraw)
        index = int (index)
        block_timestamp = int (block_timestamp)
        if args.debug:
            W ('tx: %d %s\n' % (index, dhash (txraw)[::-1].encode ('hex'),))
        try:
            test (lock_script, txraw, index, block_timestamp)
            good += 1
        except:
            W ('error: %r\n' % (coro.compact_traceback(),))
            bad += 1
            fbad.write (line)
        if args.debug:
            W ('hit <enter> to continue\n')
            raw_input()
    W ('%d good, %d bad\n' % (good, bad))
    fbad.close()

import argparse
p = argparse.ArgumentParser (description='Run the VM over a set of test txn inputs')
p.add_argument ('-d', '--debug', action='store_true', help='Have the VM print debug output', default=False)
p.add_argument ('file', help='file of test cases, one per line.', default=False)
args = p.parse_args()
test_all (args)
