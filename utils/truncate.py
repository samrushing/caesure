# -*- Mode: Python -*-

# truncate block database in a particular location.
#  useful for debugging.

import os
import argparse
from caesure.block_db import BlockDB

class GlobalState:
    pass
G = GlobalState()

p = argparse.ArgumentParser()
p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
p.add_argument ('height', type=int, help="height to truncate at")
G.args = p.parse_args()

db = G.block_db = BlockDB (read_only=True)

name = list(db.num_block[int(G.args.height)])[0]
pos  = db.blocks[name]

f = open (os.path.join (G.args.base, 'blocks.bin'), 'ab')
f.truncate (pos)
f.close()

os.unlink (os.path.join (G.args.base, 'metadata.bin'))
os.unlink (os.path.join (G.args.base, 'utxo.bin'))

print 'block database truncated at height=', G.args.height
