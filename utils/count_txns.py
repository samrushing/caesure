# -*- Mode: Python; indent-tabs-mode: nil -*-

from caesure.block_db import BlockDB
import argparse
import sys

W = sys.stderr.write

class GlobalState:
    pass
G = GlobalState()
p = argparse.ArgumentParser()
p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
G.args = p.parse_args()
db = G.block_db = BlockDB (read_only=True)

total = 0
n = 0
for block in db:
    total += len(block.transactions)
    n += 1
    if n % 1000 == 0:
        W ('[%d]' % (n,))

print 'total', total
