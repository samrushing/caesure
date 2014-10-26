# -*- Mode: Python; indent-tabs-mode: nil -*-

import coro
from caesure.bitcoin import KEY, TX
from caesure.script import *

# XXX consider piping via stdin
# $ lpython ../utils/find_multi.py 315000 316000 > multisig_tests.txt
# $ lpython test_txns.py multisig_tests.txt

def HD (s):
    return s.decode ('hex')

# XXX fuzz these guys up and force them to fail.
def test (lock_script, tx_raw, index):
    tx = TX()
    tx.unpack (tx_raw)
    m = verifying_machine (tx, index)
    tx.verify0 (index, lock_script),
    
def test_all():
    import sys
    good = 0
    bad  = 0
    
    for line in open (sys.argv[1], 'rb'):
        lock_script, txraw, index = line.split()
        lock_script = HD (lock_script)
        txraw = HD (txraw)
        index = int (index)
        try:
            test (lock_script, txraw, index)
            good += 1
        except:
            print coro.compact_traceback()
            bad += 1
    print '%d good, %d bad' % (good, bad)

test_all()
