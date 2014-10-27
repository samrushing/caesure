# -*- Mode: Python; indent-tabs-mode: nil -*-

import leveldb
import struct
from caesure.bitcoin import timer
from caesure.proto import Name
from caesure.ansi import *
from caesure.block_db import BlockDB

# a map from txname -> block,index

# we only use the first half of the tx name.

class TxMap:

    def __init__ (self, block_db, db_path):
        self.block_db = block_db
        self.txmap = leveldb.LevelDB (db_path)
        self.mount()

    def mount (self):
        try:
            block_height = self.txmap.Get ('_metadata_')
            self.block_height = int (block_height)
        except KeyError:
            self.block_height = 0
        if self.block_height < self.block_db.last_block:
            self.scan_to (self.block_height)

    def find_block_index (self, txname):
        if type(txname) is Name:
            key = str(txname)[:16]
        elif type(txname) is bytes:
            if len(txname) == 32:
                key = txname[:16]
            elif len(txname) == 64:
                key = txname.decode ('hex')[::-1][:16]
            else:
                raise KeyError (txname)
        else:
            raise KeyError (txname)
        return key, struct.unpack ('>IH', self.txmap.Get (key))

    def __getitem__ (self, txname):
        key, (height, index) = self.find_block_index (txname)
        for name in self.block_db.num_block[height]:
            block = self.block_db[name]
            tx = block.transactions[index]
            if str(tx.name).startswith (key):
                return block.name, height, index, block.transactions[index]
        raise ValueError ("this should not happen")

    def get_names (self, name, h, stop):
        names = []
        db = self.block_db
        while 1:
            if h == stop:
                break
            names.append ((name, h))
            name = db.prev[name]
            h -= 1
        names.reverse()
        return names

    def scan_to (self, stop):
        db = self.block_db
        h, name = db.get_highest_uncontested_block()
        names = self.get_names (name, h, stop)
        WR ('scanning %d blocks...\n' % (len(names),))
        t0 = timer()
        for name, height in names:
            self.feed_block (db[name], height)
            if height % 1000 == 0:
                WB ('[%d]' % (height,))
        WR ('... done (%.2f secs)\n' % (t0.end(),))
        self.txmap.Put ('_metadata_', str(height))

    def feed_block (self, block, height):
        db = self.block_db
        txmap = self.txmap
        for i, tx in enumerate (block.transactions):
            val = struct.pack ('>IH', height, i)
            txmap.Put (str(tx.name)[:16], val)

if __name__ == '__main__':
    import argparse
    class GlobalState:
        pass
    G = GlobalState()
    p = argparse.ArgumentParser()
    p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
    G.args = p.parse_args()
    db = G.block_db = BlockDB (read_only=True)
    import os
    txmap_path = os.path.join (G.args.base, 'txmap')
    txmap = TxMap (db, txmap_path)
