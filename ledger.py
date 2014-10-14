# -*- Mode: Python -*-

import struct
from caesure._script import parse_script
from caesure.script import pprint_script, OPCODES
from bitcoin import BlockDB, key_to_address, rhash, bcrepr
import caesure.proto
import cPickle
import bitcoin
import coro

from caesure.txfaa import UTXO_Map, UTXO_Scan_Map

from pprint import pprint as pp

import sys

W = sys.stderr.write

pack_u64 = caesure.proto.pack_u64

def compute_rewards (n):
    l = []
    r = 50 * 100000000
    for i in range (n):
        l.append (r)
        r /= 2
    return l

# 60 years' worth
reward_schedule = compute_rewards (15)

def compute_reward (height):
    return reward_schedule [height // 210000]

import time

class timer:
    def __init__ (self):
        self.start = time.time()
    def end (self):
        return time.time() - self.start

class RecentBlocks:

    def __init__ (self, ledger, db):
        self.db = db
        # we always begin with one tip.
        self.tips = {ledger.height : ledger}
        # we keep a horizon of this many blocks back from the tip.
        self.horizon = 20

    def remove_old_tips (self):
        # first, find the main chain
        tip = 0
        for h, l in self.tips.iteritems():
            tip = max (h, tip)
        if tip is 0:
            return
        else:
            # now, forget any tips beyond the horizon
            for h, l in self.tips.items():
                if tip - h > self.horizon:
                    del self.tips[h]

    def new_block (self, block, verify=False):
        tip = None
        for h, l in self.tips.iteritems():
            if block.prev_block == l.block_name:
                tip = h, l
                break
        if tip is None:
            raise ValueError ("new block does not chain %064x" % (block.name,))
        h, l = tip
        self.tips[h+1] = l.extend (block, h + 1, verify)
        del self.tips[h]
        self.remove_old_tips()
        
class LedgerState:

    save_path = '/usr/local/caesure/utxo.bin'

    def __init__ (self, load=False):
        self.outpoints = UTXO_Map()
        self.block_name = bitcoin.ZERO_NAME
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
        # XXX use a .tmp file and os.rename
        f = open (self.save_path, 'wb')
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
        W ('[saved outpoints %d/%d entries]' % (len(self.outpoints), n))
        f.close()

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
            self.block_name = bitcoin.Name (self.block_name)
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
def catch_up (db):

    global ledger, recent_blocks

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
                if name == bitcoin.ZERO_NAME:
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
        if i % 10000 == 0:
            W('%d ' % (i,))
        if i == ledger.height + 1:
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
    recent_blocks = RecentBlocks (ledger, db)
    print repr(ledger.block_name)
    names = db.next (ledger.block_name)
    while names:
        name = names.pop()
        print 'adding %r' % (name,)
        recent_blocks.new_block (db[name])
        names += db.next (name)

    if __name__ == '__main__':
        coro.set_exit()

    return recent_blocks

if __name__ == '__main__':
    import bitcoin
    db = BlockDB (read_only=True)
    bitcoin.the_block_db = db
    if '-c' not in sys.argv:
        import coro
        import coro.backdoor
        coro.spawn (catch_up, db)
        coro.spawn (coro.backdoor.serve, 8025)
        coro.event_loop()

    
