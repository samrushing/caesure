# -*- Mode: Python -*-

import os
import struct

from caesure.script import pprint_script, OPCODES, parse_script, is_unspendable
from caesure.block_db import BlockDB
from caesure.bitcoin import *
from caesure.txfaa import UTXO_Map, UTXO_Scan_Map

import coro

from pprint import pprint as pp

import sys

W = sys.stderr.write

class RecentBlocks:

    def __init__ (self, ledger, db):
        self.db = db
        # we always begin with one tip.
        self.blocks = {ledger.block_name : ledger}
        # these will be recomputed upon the call to self.new_block()
        self.root = set([ledger])
        self.leaves = set([ledger])
        # we keep a horizon of this many blocks back from the tip.
        self.horizon = 20
        self.highest = 0

    def new_block (self, block, verify=False):
        from __main__ import G
        tip = None
        for name, lx in self.blocks.iteritems():
            if block.prev_block == lx.block_name:
                tip = lx
                break
        if tip is None:
            height = block.get_height()
            if height > self.highest:
                # I think this happens when the hoover delivers blocks out of order.
                # we know the previous block is in the database...
                self.new_block (G.block_db[block.prev_block], verify)
                self.new_block (block, verify)
            elif height <= (self.highest - self.horizon):
                G.log ('recent', 'stale', height, str(block.name), str(block.prev_block))
            else:
                G.log ('recent', 'nochain', height, str(block.name), str(block.prev_block))
        else:
            t0 = timer()
            self.blocks[block.name] = tip.extend (block, tip.height + 1, verify)
            W ('[tip.extend %0.2f]' % (t0.end(),))
            if len(self.blocks) > 2:
                # otherwise we are in 'catch up' mode.
                self.trim()
        
    def find_lowest_common_ancestor (self, leaves, db):
        # find the lowest common ancestor of <leaves>.
        # http://en.wikipedia.org/wiki/Lowest_common_ancestor
        # aka MRCA 'most recent common ancestor'.
        search = leaves[:]
        while 1:
            if len(search) == 1:
                # we're done.
                break
            else:
                # find the highest leaf.
                search.sort()
                # scoot it back by one level.
                h, name = search[-1]
                scoot = (h-1, db.prev[name])
                if scoot in search:
                    # we found a common ancestor
                    del search[-1]
                else:
                    search[-1] = scoot
        return search[0][1]

    def trim (self):
        # this is more complex than I would like, but it solves a difficult problem:
        #  we need to trim the set of recent blocks back to our horizon, *except* in
        #  the case where the most recent common ancestor is *outside* the horizon.
        from __main__ import G
        db = G.block_db
        # get them sorted by height
        blocks = [(lx.height, lx) for lx in self.blocks.values()]
        blocks.sort()
        self.highest = blocks[-1][0]
        # --- identify leaves within our horizon ---
        # note: we can't use db.next[name] to identify leaves because
        # the db is often past our ledger on startup, and leaves in
        # self.blocks can have children in the db.
        cutoff = self.highest - self.horizon
        names = set (self.blocks.keys())
        prevs = set ([db.prev[lx.block_name] for lx in self.blocks.values()])
        leaves = names.difference (prevs)
        leaves = [self.blocks[name] for name in leaves]
        # only those leaves within our horizon...
        leaves = [(lx.height, lx.block_name) for lx in leaves if lx.height >= cutoff]
        leaves.sort()
        lca = self.find_lowest_common_ancestor (leaves, db)
        lca = self.blocks[lca]
        if lca.height < cutoff:
            # if the lca is behind the horizon, we must keep it.
            cutoff = lca.height
            self.root = lca
            G.log ('lca cutoff', str(lca.block_name))
        else:
            # lca is inside the horizon: crawl back til we hit the cutoff.
            root = lca
            while root.height > cutoff:
                prev = db.prev[root.block_name]
                if self.blocks.has_key (prev):
                    root = self.blocks[prev]
                else:
                    # we are building the ledger and don't have horizon nodes yet.
                    break
            self.root = root
        # perform the trim, identify root and leaves.
        for h, lx in blocks:
            if h < cutoff:
                del self.blocks[lx.block_name]
        self.leaves = set (self.blocks[x[1]] for x in leaves)

    def save_ledger_thread (self):
        while 1:
            # roughly once an hour, flush the oldest recent block's ledger.
            coro.sleep_relative (67 * 60)
            self.root.save_state()

class LedgerState:

    save_path = 'utxo.bin'
    do_yields = True

    def __init__ (self, load=False):
        self.outpoints = UTXO_Map()
        self.block_name = ZERO_NAME
        self.height = -1
        self.total = 0
        self.lost = 0
        self.fees = 0
        if load:
            from __main__ import G
            save_path = os.path.join (G.args.base, self.save_path)
            self.load_state (save_path)

    def clone (self):
        ob = LedgerState()
        ob.block_name = self.block_name
        ob.height = self.height
        ob.total = self.total
        ob.lost = self.lost
        ob.fees = self.fees
        ob.outpoints = self.outpoints.copy()
        return ob

    def extend (self, block, height, verify=True):
        ob = self.clone()
        ob.feed_block (block, height, verify)
        return ob

    def get_total_outpoints (self):
        total = 0
        for k, v in self.outpoints:
            total += len(v)
        return total

    cache_version = 3

    def save_state (self):
        from coro.asn1.data_file import DataFileWriter
        from __main__ import G
        save_path = os.path.join (G.args.base, self.save_path)
        f = open (save_path + '.tmp', 'wb')
        df = DataFileWriter (f)
        t0 = timer()
        df.write_object ([
            self.cache_version,
            self.height,
            str(self.block_name),
            self.total,
            self.lost,
            self.fees,
            len(self.outpoints)
        ])
        n = 0
        for item in self.outpoints:
            df.write_object (item)
            n += 1
            if n % 1000 == 999:
                coro.yield_slice()
        f.close()
        os.rename (save_path + '.tmp', save_path)
        W ('[saved outpoints %d/%d entries %.02fs]' % (len(self.outpoints), n, t0.end()))

    def load_state (self, path=None):
        from coro.asn1.data_file import DataFileReader
        from __main__ import G
        if path is None:
            path = os.path.join (G.args.base, self.save_path)
        W ('loading outpoints cache...')
        t0 = timer()
        try:
            f = open (path, 'rb')
            df = DataFileReader (f)
            info = df.read_object()
            # XXX if we see an older version, pretend it's not there so it will be rebuilt.
            assert (info[0] == self.cache_version)  # version
            [_, self.height, self.block_name, self.total, self.lost, self.fees, size] = info
            W (' height = %d size = %d ...' % (self.height, size))
            self.block_name = Name (self.block_name)
            n = [0]
            df.next = df.read_object
            self.outpoints.build (df, size)
            f.close()
            W ('[loaded outpoints %d/%d entries]' % (len(self.outpoints),n[0]))
            W ('\nlast block: %d %064x\n' % (self.height, self.block_name))
        except IOError:
            pass
        W ('...done (%.2fs)\n' % (t0.end(),))

    def store_outputs (self, tx):
        output_sum = 0
        outputs = []
        for i, (amt, lock_script) in enumerate (tx.outputs):
            #if len(lock_script) > 500:
            #    W ('%r len(script) = %d\n' % (tx.name, len(lock_script)))
            if not is_unspendable (lock_script):
                outputs.append ((i, amt, lock_script))
            output_sum += amt
        self.outpoints.new_entry (str(tx.name), outputs)
        self.total += output_sum
        return output_sum

    def get_utxo (self, name, index):
        return self.outpoints.get_utxo (name, index)

    def feed_tx (self, index, tx, verify=False):
        input_sum = 0
        for j in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[j]
            outstr = str(outpoint)
            amt, lock_script = self.outpoints.pop_utxo (outstr, index)
            if verify:
                try:
                    tx.verify (j, lock_script, b.timestamp)
                except VerifyError:
                    self.outpoints.new_entry (outstr, [(index, amt, lock_script)])
                    raise
            input_sum += amt
            if self.do_yields and j % 20 == 19:
                coro.yield_slice()
        output_sum = self.store_outputs (tx)
        return input_sum, output_sum

    def feed_block (self, b, height, verify=False):
        if b.prev_block != self.block_name:
            raise ValueError (b.prev_block, self.block_name)
        # assume coinbase is ok for now
        tx0 = b.transactions[0]
        reward0 = self.store_outputs (tx0)
        fees = 0
        for i, tx in enumerate (b.transactions):
            if i == 0:
                continue
            input_sum, output_sum = self.feed_tx (i, tx, verify)
            fees += input_sum - output_sum
            self.total -= input_sum
        self.fees += fees
        reward1 = compute_reward (height)
        if reward1 + fees != reward0:
            lost = (reward1 + fees) - reward0
            #W ('reward mismatch height=%d lost=%s\n' % (height, lost))
            self.lost += lost
        self.height = height
        self.block_name = b.name

# XXX a version of this that feeds all blocks, not just the main chain.
#   hmmmm how about one that feeds them in timestamp order!
def catch_up (G):

    db = G.block_db

    def get_names():
        "get the chain of all block names, ignoring forks"
        if not db.num_block:
            return []
        else:
            names = list (db.num_block[db.last_block])
            # XXX handle this case
            assert (len(names) == 1)
            b = db[names[0]]
            r = []
            name = b.name
            while 1:
                r.append(name)
                name = db.prev[name]
                if name == ZERO_NAME:
                    break
            r.reverse()
            return r

    ledger = LedgerState (load=True)

    if len(ledger.outpoints) == 0:
        W ('no outpoints cache.  performing fast scan [30-45 minutes]\n')
        ledger.outpoints = UTXO_Scan_Map()
        fast_scan = True
    else:
        fast_scan = False

    t0 = timer()
    names = get_names()
    #if fast_scan:
    #    # TRIM FOR TESTING ONLY
    #    names = names[:225430]
    # drop back by a 20-block horizon
    most_names = names[:-20]
    i = 0
    fed = 0
    for name in most_names:
        if i == ledger.height + 1:
            if i % 1000 == 0:
                W('%d ' % (i,))
            block = db[name]
            ledger.feed_block (block, i)
            fed += 1
        elif i <= ledger.height:
            pass
        else:
            W('oops, block too high?\n')
            import pdb
            pdb.set_trace()
        i += 1
        coro.yield_slice()

    W('\n')
    W('       total=%20s\n' % bcrepr(ledger.total + ledger.lost))
    W('        live=%20s\n' % bcrepr(ledger.total))
    W('        lost=%20s\n' % bcrepr(ledger.lost))
    W('        fees=%20s\n' % bcrepr(ledger.fees))
    W('(%.2fs to scan %d blocks into ledger)\n' % (t0.end(), fed))
    if fed > 150:
        W ('saving... ledger.block_name = %064x\n' % (ledger.block_name,))
        ledger.save_state()
    if fast_scan:
        W ('done with fast scan, reloading...\n')
        ledger.outpoints = None
        ledger.outpoints = UTXO_Map()
        ledger.load_state()

    W ('topping off recent_blocks...\n')
    G.recent_blocks = RecentBlocks (ledger, db)
    names = db.next (ledger.block_name)
    while names:
        name = names.pop()
        W ('adding %r\n' % (name,))
        G.recent_blocks.new_block (db[name])
        names += db.next (name)

    if __name__ == '__main__':
        coro.set_exit()

    return G.recent_blocks



if __name__ == '__main__':
    import argparse
    class GlobalState:
        pass
    G = GlobalState()
    p = argparse.ArgumentParser()
    p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
    G.args = p.parse_args()
    G.block_db = BlockDB (read_only=True)
    if '-c' not in sys.argv:
        import coro
        import coro.backdoor
        coro.spawn (catch_up, G)
        coro.spawn (coro.backdoor.serve, 8025)
        coro.event_loop()
