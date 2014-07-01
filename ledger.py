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

class TransactionMap:
    def __init__ (self):
        self.outpoints = UTXO_Map()
        self.height = -1
        self.total = 0
        self.lost = 0
        self.fees = 0
        self.load_state()
        if len(self.outpoints) == 0:
            W ('no outpoint cache.  doing fast scan (15+min)...\n')
            self.outpoints = UTXO_Scan_Map()

    def get_total_outpoints (self):
        total = 0
        for k, v in self.outpoints:
            total += len(v)
        return total

    def save_state (self):
        f = open ('outpoints.bin', 'wb')
        cPickle.dump ([1, self.height, self.total, self.lost, self.fees, len(self.outpoints)], f, 2)
        for item in self.outpoints:
            cPickle.dump (item, f, 2)
        f.close()

    def load_state (self):
        W ('loading outpoints cache...')
        t0 = bitcoin.timer()
        try:
            f = open ('outpoints.bin', 'rb')
            info = cPickle.load (f)
            assert (info[0] == 1)  # version
            [_, self.height, self.total, self.lost, self.fees, size] = info
            def gen():
                while 1:
                    try:
                        x = cPickle.load (f)
                        yield x
                    except EOFError:
                        break
            self.outpoints.build (gen(), size)
            f.close()
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

    def feed_block (self, b, height, verify=False):
        # assume coinbase is ok for now
        tx0 = b.transactions[0]
        reward0 = self.store_outputs (tx0)
        fees = 0
        for tx in b.transactions[1:]:
            # verify each transaction
            # first, we need the output script for each of the inputs
            input_sum = 0
            for i in range (len (tx.inputs)):
                (outpoint, index), script, sequence = tx.inputs[i]
                amt, oscript = self.outpoints.pop_utxo (str(outpoint), index)
                if verify:
                    tx.verify0 (i, oscript)
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
        self.height = height

    def catch_up (self, db):

        def get_names():
            b = db.by_num(db.last_block)
            r = []
            name = b.name
            while 1:
                r.append(name)
                name = db.prev[name]
                if name == bitcoin.ZERO_NAME:
                    break

            r.reverse()
            return r

        t0 = timer()
        names = get_names()
        i = 0
        fed = 0
        for name in names:
            if i % 10000 == 0:
                W('%d ' % (i,))
            if i == self.height + 1:
                self.feed_block(db[name], i)
                fed += 1
            elif i <= self.height:
                pass
            else:
                W('oops, block too high?\n')
                import pdb
                pdb.set_trace()
            i += 1
            coro.yield_slice()

        W('\n')
        W('       total=%20s\n' % bcrepr(self.total + self.lost))
        W('        live=%20s\n' % bcrepr(self.total))
        W('        lost=%20s\n' % bcrepr(self.lost))
        W('        fees=%20s\n' % bcrepr(self.fees))
        W('(%.2fs to scan)\n' % (t0.end(),))
        if fed > 150:
            self.save_state()
        if __name__ == '__main__':
            coro.set_exit()
        elif isinstance (self.outpoints, UTXO_Scan_Map):
            W ('done with fast scan, reloading...\n')
            self.outpoints = UTXO_Map()
            self.load_state()

if __name__ == '__main__':
    import bitcoin
    db = BlockDB (read_only=True)
    bitcoin.the_block_db = db
    txmap = TransactionMap()
    if '-c' not in sys.argv:
        import coro
        import coro.backdoor
        coro.spawn (txmap.catch_up, db)
        coro.spawn (coro.backdoor.serve, 8025)
        coro.event_loop()

    
