# -*- Mode: Python -*-

from caesure.script import parse_script, pprint_script, ScriptError, OPCODES
from caesure._script import ScriptError
from caesure.block_db import BlockDB
from caesure.proto import Name

# find spends of non-p2sh CHECKMULTISIG txns. (this is for finding test cases).

def is_checkmultisig (s):
    x = s[-1]
    return x[0] == KIND_CHECK and x[1] == OPCODES.OP_CHECKMULTISIG

def find (db, start, stop):
    multi = {}
    # find some MULTISIG outputs...
    for i in range (start, stop):
        b = db.by_num (i)
        for tx in b.transactions:
            for j, out in enumerate (tx.outputs):
                if out[1] and out[1][-1] == chr(OPCODES.OP_CHECKMULTISIG):
                    multi[(tx.name, j)] = out[1]
    # search the same range for spends of those outputs...
    for i in range (start, stop):
        b = db.by_num (i)
        for tx in b.transactions:
            for j, (outpoint, unlock, sequence) in enumerate (tx.inputs):
                if multi.has_key (outpoint):
                    print multi[outpoint].encode ('hex'), tx.raw.encode('hex'), j, b.timestamp

# try: python find_multi.py 315000 316000
if __name__ == '__main__':
    import argparse
    class GlobalState:
        pass
    G = GlobalState()
    p = argparse.ArgumentParser()
    p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
    p.add_argument ('start', type=int, help='starting block height')
    p.add_argument ('stop', type=int, help='stopping block height')
    G.args = p.parse_args()
    db = G.block_db = BlockDB (read_only=True)
    find (db, G.args.start, G.args.stop)
