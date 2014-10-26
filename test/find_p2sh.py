# -*- Mode: Python -*-

from caesure.script import parse_script, pprint_script, ScriptError, OPCODES
from caesure._script import ScriptError
from caesure.block_db import BlockDB
from caesure.proto import Name

# find spends of p2sh txns. (this is for finding test cases).

def is_p2sh (s):
    return (
        len(s) == 3
        and s[0] == (2, OPCODES.OP_HASH160)
        and s[2] == (2, OPCODES.OP_EQUAL)
        and s[1][0] == 0
        and len(s[1][1]) == 20
    )

def find (db, start, stop):
    multi = {}
    # find some P2SH outputs...
    for i in range (start, stop):
        b = db.by_num (i)
        for tx in b.transactions:
            for j, out in enumerate (tx.outputs):
                if is_p2sh (parse_script (out[1])):
                    multi[(tx.name, j)] = out[1]
    # search the same range for spends of those outputs...
    for i in range (start, stop):
        b = db.by_num (i)
        for tx in b.transactions:
            for j, (outpoint, unlock, sequence) in enumerate (tx.inputs):
                if multi.has_key (outpoint):
                    print multi[outpoint].encode ('hex'), tx.raw.encode('hex'), j

# try: python find_p2sh.py 310000 312000
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
