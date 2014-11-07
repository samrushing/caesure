# -*- Mode: Python; indent-tabs-mode: nil -*-

# verify the entire block chain.

from caesure.script import parse_script, pprint_script, ScriptError, OPCODES
from caesure._script import ScriptError
from caesure.block_db import BlockDB
from caesure.proto import Name
from caesure.ledger import LedgerState
from caesure.ansi import *

import sys
W = sys.stderr.write

def get_names (db, name, h, stop):
    names = []
    while 1:
        if h == stop:
            break
        names.append ((name, h))
        name = db.prev[name]
        h -= 1
    names.reverse()
    return names

fails = open ('fails.txt', 'wb')

# wrap verify to catch all failures, while pretending they didn't happen.
from caesure.bitcoin import TX
original_verify = TX.verify

def verify_wrapper (self, index, lock_script, block_timestamp):
    try:
        original_verify (self, index, lock_script, block_timestamp)
    except:
        W ('%064x %d failed\n' % (self.name, index))
        fails.write (
            '#%s\n%s %s %d %d\n' % (
                hex(self.name),
                lock_script.encode ('hex'),
                self.raw.encode ('hex'),
                index,
                block_timestamp
            )
        )

TX.verify = verify_wrapper

def main (db, G):
    h, name = db.get_highest_uncontested_block()
    names = get_names (db, name, h, -1)
    WR ('scanning %d blocks...\n' % (len(names),))
    lx = LedgerState (load=False)
    lx.do_yields = False
    height = 0
    for name, height in names:
        #W ('name=%r, height=%d\n' % (repr(name), height))
        b = db[name]
        #W ('b=%r\n' % (b,))
        lx.feed_block (b, height, verify=True)
        if height % 1000 == 0:
            WB ('[%d]' % (height,))
    
if __name__ == '__main__':
    import argparse
    class GlobalState:
        pass
    G = GlobalState()
    p = argparse.ArgumentParser()
    p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
    p.add_argument ('--stop', type=int, help='stopping block height', default=10000)
    G.args = p.parse_args()
    db = G.block_db = BlockDB (read_only=True)
    #import coro.backdoor
    #coro.spawn (coro.backdoor.serve, unix_path='/tmp/verify.bd')
    #coro.spawn (main, db, G)
    #coro.event_loop()
    main (db, G)
    
