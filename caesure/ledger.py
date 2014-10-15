# -*- Mode: Python -*-

import os
import struct

from caesure.script import pprint_script, OPCODES, parse_script
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
        # we keep a horizon of this many blocks back from the tip.
        self.horizon = 20

    def find_tips (self):
        "returns <set-of-oldest-blocks>, <set-of-tips>"
        from __main__ import G
        db = G.block_db
        g0 = set (self.blocks.keys())
        g1 = set()
        g2 = set()
        g3 = set()
        for name, lx in self.blocks.iteritems():
            back = db.prev[lx.block_name]
            # g1 = nodes pointing out of the set (i.e., oldest/horizon).
            if back not in g0:
                g1.add (lx)
            # g2 = back pointers of all nodes in the set.
            g2.add (back)
        for name, lx in self.blocks.iteritems():
            if name not in g2:
                # nodes who are not pointed to by the set (i.e., tips)
                g3.add (lx)
        return g1, g3

    def remove_old_blocks (self):
        # first, find the highest block.
        blocks = [(lx.height, lx) for lx in self.blocks.values()]
        blocks.sort()
        if not blocks:
            return
        else:
            highest = blocks[-1][0]
            # now, forget any blocks beyond the horizon
            for h, lx in blocks:
                if highest - h > self.horizon:
                    del self.blocks[lx.block_name]

    def new_block (self, block, verify=False):
        from __main__ import G
        tip = None
        for name, lx in self.blocks.iteritems():
            if block.prev_block == lx.block_name:
                tip = lx
                break
        if tip is None:
            if G.block_db.has_key (block.prev_block):
                self.new_block (G.block_db[block.prev_block])
                self.new_block (block)
            else:
                # XXX should be unreachable?
                raise ValueError ("new block does not chain %064x" % (block.name,))
        else:
            self.blocks[block.name] = tip.extend (block, tip.height + 1, verify)
            self.remove_old_blocks()
        
class LedgerState:

    save_path = '/usr/local/caesure/utxo.bin'

    def __init__ (self, load=False):
        self.outpoints = UTXO_Map()
        self.block_name = ZERO_NAME
        self.height = -1
        self.total = 0
        self.lost = 0
        self.fees = 0
        if load:
            self.load_state (self.save_path)

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

    cache_version = 2

    def save_state (self):
        from coro.asn1.data_file import DataFileWriter
        f = open (self.save_path + '.tmp', 'wb')
        df = DataFileWriter (f)
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
        os.rename (self.save_path + '.tmp', self.save_path)
        W ('[saved outpoints %d/%d entries]' % (len(self.outpoints), n))

    def load_state (self, path=None):
        from coro.asn1.data_file import DataFileReader
        if path is None:
            path = self.save_path
        W ('loading outpoints cache...')
        t0 = timer()
        try:
            f = open (path, 'rb')
            df = DataFileReader (f)
            info = df.read_object()
            assert (info[0] == self.cache_version)  # version
            [_, self.height, self.block_name, self.total, self.lost, self.fees, size] = info
            W (' height = %d ...' % (self.height,))
            self.block_name = Name (self.block_name)
            n = [0]
            def gen():
                while 1:
                    try:
                        x = df.read_object()
                        n[0] += 1
                        yield x
                    except EOFError:
                        break
            self.outpoints.build (gen(), size)
            f.close()
            W ('[loaded outpoints %d/%d entries]' % (len(self.outpoints),n[0]))
            W ('\nlast block: %d %064x\n' % (self.height, self.block_name))
        except IOError:
            pass
        W ('...done (%.2fs)\n' % (t0.end(),))

    def store_outputs (self, tx):
        output_sum = 0
        i = 0
        outputs = []
        for amt, pk_script in tx.outputs:
            #if len(pk_script) > 500:
            #    W ('%r len(script) = %d\n' % (tx.name, len(pk_script)))
            outputs.append ((i, amt, pk_script))
            if amt > 0:
                output_sum += amt
            i += 1
        self.outpoints.new_entry (str(tx.name), outputs)
        self.total += output_sum
        return output_sum

    def get_utxo (self, name, index):
        return self.outpoints.get_utxo (name, index)

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
            # verify each transaction
            # first, we need the output script for each of the inputs
            input_sum = 0
            for j in range (len (tx.inputs)):
                (outpoint, index), script, sequence = tx.inputs[j]
                amt, oscript = self.outpoints.pop_utxo (str(outpoint), index)
                #W ('.')
                if verify:
                    tx.verify0 (j, oscript)
                input_sum += amt
            output_sum = self.store_outputs (tx)
            fees += input_sum - output_sum
            self.total -= input_sum
        self.fees += fees
        reward1 = compute_reward (height)
        if reward1 + fees != reward0:
            lost = (reward1 + fees) - reward0
            #W ('reward mismatch height=%d lost=%s\n' % (height, lost))
            self.lost += lost
        self.block = b
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
        W ('no outpoints cache.  performing fast scan [15+ minutes]\n')
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
    # lots of disk i/o leads to multi-second latencies, ignore for now.
    # [XXX looking into using a disk i/o thread for this?]
    coro.set_latency_warning (0)
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
    coro.set_latency_warning (1)

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
    class GlobalState:
        pass
    G = GlobalState()
    import bitcoin
    G.block_db = BlockDB (read_only=True)
    if '-c' not in sys.argv:
        import coro
        import coro.backdoor
        coro.spawn (catch_up, G)
        coro.spawn (coro.backdoor.serve, 8025)
        coro.event_loop()
