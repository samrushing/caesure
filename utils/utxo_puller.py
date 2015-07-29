#!/usr/bin/env python
# -*- Mode: Python; indent-tabs-mode: nil -*-

# build/refresh a utxo database directly from a local (full-blockchain) node.

# $ lpython utxo_puller.py -b /Volumes/drive3/caesure/ 127.0.0.1:8333

# as of Jul 2015, this can build a new utxo db directly from another node
#   in about 50 minutes.

import argparse
import os
import coro
import time

from coro.log import NoFacility

LOG = NoFacility ()

from caesure.ansi import *
from caesure.connection import BaseConnection, parse_addr_arg
from caesure.global_state import GlobalState
from caesure.proto import unpack_version, unpack_inv, unpack_headers, pack_getblocks
from caesure.bitcoin import *
from caesure.block_db import BlockDB, BLOCK
from caesure._utxo_scan import UTXO_Scan_Map
from caesure._utxo import UTXO_Map
from caesure.utxo.ldb import UTXO_leveldb
from caesure.ledger import LedgerState

class UTXO_Puller (BaseConnection):

    packet = True

    def __init__ (self, G, my_addr, other_addr):
        BaseConnection.__init__ (self, my_addr, other_addr, verbose=G.verbose)
        self.waiting = {}
        self.G = G
        self.log_fun = G.log

    def wait_for (self, key):
        "wait on a CV with <key> (used by get_block, etc...)"
        if not self.waiting.has_key (key):
            self.waiting[key] = coro.condition_variable()
        try:
            return self.waiting[key].wait()
        finally:
            del self.waiting[key]

    def getheaders (self, hashes):
        # on this connection only, download the entire chain of headers from our
        #   tip to the other side's tip.
        hashes.append (ZERO_NAME)
        chain = [hashes[0]]
        while 1:
            # getheaders and getblocks have identical args/layout.
            self.send_packet ('getheaders', pack_getblocks (self.version, hashes))
            _, data = coro.with_timeout (90, self.wait_for, 'headers')
            blocks = unpack_headers (data)
            if len(blocks) == 0:
                break
            else:
                for block in blocks:
                    if block.prev_block == chain[-1]:
                        chain.append (block.name)
                    else:
                        self.G.log ('getheaders', 'nochain')
                        return []
                hashes[0] = chain[-1]
        return chain

    def do_command (self, cmd, data):
        if self.waiting.has_key (cmd):
            self.waiting[cmd].wake_all ((cmd, data))
        BaseConnection.do_command (self, cmd, data)

    def cmd_inv (self, data):
        pass

    def cmd_block (self, payload):
        global in_flight, total_bytes
        total_bytes += len(payload)
        in_flight -= 1
        if in_flight < G.args.inflight:
            in_flight_cv.wake_all()
        b = BLOCK()
        b.unpack (payload)
        lx = self.G.ledger
        lx.feed_block (b, lx.height + 1)
        if lx.height % 1000 == 0:
            WB ('[%d]' % lx.height)

    def cmd_tx (self, payload):
        pass

    def cmd_addr (self, payload):
        pass

    def cmd_headers (self, payload):
        pass

    def cmd_getdata (self, payload):
        pass

    def cmd_getheaders (self, payload):
        # newer bitcoind asks for these upon connection. ignore.
        pass

# mainnet genesis (XXX support testnet)
genesis = BLOCK()
genesis.unpack (
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
    '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c'
    '0101000000010000000000000000000000000000000000000000000000000000000000000000ffff'
    'ffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c'
    '6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73'
    'ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a6'
    '7962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
    'ac00000000'.decode ('hex')
)

MB = 1024 * 1024
GB = 1024 * MB

def pull_blocks (G):
    global in_flight
    addr0 = ('127.0.0.1', 0)
    addr1 = parse_addr_arg (G.args.connect)
    cp = UTXO_Puller (G, addr0, addr1)
    cp.wait_for ('verack')
    LOG ('downloading headers...')
    hashes = [G.ledger.block_name]
    names = cp.getheaders (hashes)
    LOG (len(names), 'headers')
    start = time.time()
    coro.spawn (rate_thread)
    LOG ('got %d names...' % (len(names),))
    # XXX DEBUG XXX
    #names = names[:100001]
    # XXX DEBUG XXX
    # Note: skip the first name, we already have it.
    for i in range (1, len (names), 50):
        chunk = names[i:i+50]
        cp.getdata ([(OBJ_BLOCK, name) for name in chunk])
        in_flight += len(chunk)
        in_flight_cv.wait()
    # let it finish
    while 1:
        coro.sleep_relative (1)
        if in_flight == 0:
            break
    stop = time.time()
    WB (
        '\ntransferred %.2f GB in %d secs (%.2f MB/s)\n' % (
            float(total_bytes) / GB,
            stop - start,
            (float(total_bytes) / MB) / (stop - start)
        )
    )
    G.done_cv.wake_all()

total_bytes = 0

def rate_thread():
    n0 = 0
    while 1:
        coro.sleep_relative (10)
        n1 = total_bytes
        delta = n1 - n0
        n0 = n1
        WR ('(%.2f)' % (delta / 10485760.))

def main (G):
    G.done_cv = coro.condition_variable()
    if G.args.leveldb:
        utxomap = UTXO_leveldb
    else:
        utxomap = UTXO_Scan_Map
    if os.path.exists (os.path.join (G.args.base, LedgerState.save_path)):
        # XXX allow leveldb here
        G.ledger = LedgerState (load=True, utxo_factory=UTXO_Map)
    else:
        LOG ('building a new utxo database using UTXO_Scan_Map')
        G.ledger = LedgerState (load=False, utxo_factory=utxomap)
    # must feed at least the genesis block in...
    if G.ledger.height == -1:
        G.ledger.feed_block (genesis, 0)
    coro.spawn (pull_blocks, G)
    G.done_cv.wait()
    LOG ('saving final UTXO database...')
    G.ledger.save_state()
    coro.set_exit()

G = GlobalState()

p = argparse.ArgumentParser (description='Pull a copy of the blockchain from another node.')
p.add_argument ('connect', help="connect to this address", metavar='IP:PORT')
p.add_argument ('-i', '--inflight', help='number of blocks in flight.', type=int, default=20)
p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
p.add_argument ('-v', '--verbose', help='verbose output', action='store_true')
p.add_argument ('-l', '--leveldb', help='use leveldb', action='store_true')

G.args = p.parse_args()
G.args.packet = False
G.log = LOG
G.verbose = G.args.verbose

# tried to use inverted_semaphore here, couldn't get it to work.
in_flight = 0
in_flight_cv = coro.condition_variable()

import coro.backdoor
coro.spawn (coro.backdoor.serve, unix_path='/tmp/utxo_puller.bd')

coro.spawn (main, G)
coro.event_loop()
