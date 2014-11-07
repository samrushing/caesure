# -*- Mode: Python; indent-tabs-mode: nil -*-

# verify the entire block chain.

import struct

from caesure.bitcoin import compute_reward
from caesure.script import parse_script, pprint_script, ScriptError, OPCODES
from caesure._script import ScriptError
from caesure.block_db import BlockDB
from caesure.proto import Name
from caesure.ledger import LedgerState
from caesure.ansi import *

from coro.asn1.python import encode, decode

import os

class VerifyClient:

    def __init__ (self, G, fifo):
        self.G = G
        self.fifo = fifo
        self.dest = os.path.join (G.args.base, G.args.file)
        self.sock = coro.sock (coro.AF.UNIX, coro.SOCK.STREAM)
        self.sock.connect (self.dest)
        coro.spawn (self.go)

    def go (self):
        while 1:
            co, tx, timestamp, locks = self.fifo.pop()
            pkt = encode ([timestamp, tx.raw, locks])
            self.sock.writev ([struct.pack ('>I', len(pkt)), pkt])
            pktlen = self.sock.recv_exact (4)
            if not pktlen:
                break
            else:
                pktlen, = struct.unpack ('>I', pktlen)
                pkt = self.sock.recv_exact (pktlen)
                result, size = decode (pkt)
                assert (pktlen == size)
                co.schedule (result)

class Pool:

    def __init__ (self, G):
        self.fifo = coro.fifo()
        for i in range (G.args.nthreads):
            coro.spawn (VerifyClient, G, self.fifo)

    def request (self, tx, timestamp, lock_scripts):
        me = coro.current()
        self.fifo.push ((me, tx, timestamp, lock_scripts))
        return me._yield()

class ParallelLedgerState (LedgerState):

    def feed_block (self, b, height, verify=False):
        if b.prev_block != self.block_name:
            raise ValueError (b.prev_block, self.block_name)
        # assume coinbase is ok for now
        tx0 = b.transactions[0]
        reward0 = self.store_outputs (tx0)
        txns = set(b.transactions[1:])
        while len(txns):
            # first... let's scan for all txns that are not dependent on this block.
            # [another way to do this: eliminate all txns that spend outputs from this set]
            independent = set()
            for i, tx in enumerate (txns):
                flag = True
                for j in range (len (tx.inputs)):
                    (outpoint, index), script, sequence = tx.inputs[j]
                    try:
                        self.outpoints.get_utxo (str(outpoint), index)
                    except KeyError:
                        flag = False
                        break
                if flag:
                    independent.add (tx)
            if not len(independent):
                raise ValueError
            self.verify_txns (list(independent), b)
            txns.difference_update (independent)

        self.height = height
        self.block_name = b.name

    def verify_txns (self, txns, b):
        for i in range (0, len (txns), 20):
            #W ('doing in_parallel...\n')
            results = coro.in_parallel ([(self.verify_txn, (tx, b)) for tx in txns[i:i+20]])
            for tx in txns[i:i+20]:
                self.store_outputs (tx)

    def verify_txn (self, tx, b):
        lock_scripts = []
        input_sum = 0
        for i in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[i]
            amt, oscript = self.outpoints.get_utxo (str(outpoint), index)
            lock_scripts.append (oscript)
            input_sum += amt
        result = G.pool.request (tx, b.timestamp, lock_scripts)
        #W ('[%r]' % (result,))
        if result is not True:
            W ('failed to validate %r\n' % (tx.name,))
        return input_sum

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

def main (db, G):
    h, name = db.get_highest_uncontested_block()
    names = get_names (db, name, h, -1)
    WR ('scanning %d blocks...\n' % (len(names),))
    lx = ParallelLedgerState (load=False)
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
    p.add_argument ('-f', '--file', help='server socket filename', default='verifyd.sock', metavar='PATH')
    p.add_argument ('--nthreads', type=int, help='number of verifyd client threads', default=8)
    G.args = p.parse_args()
    db = G.block_db = BlockDB (read_only=True)
    G.pool = Pool (G)
    coro.spawn (main, db, G)
    coro.event_loop()
