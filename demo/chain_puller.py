#!/usr/bin/env python
# -*- Mode: Python; indent-tabs-mode: nil -*-

# pull a copy of the blockchain from a (hopefully) local node.

# $ lpython chain_puller.py -b /Volumes/drive3/caesure/ 127.0.0.1:8333
# reading block headers...starting at pos 0...done. scanned 0 blocks in 0.00 secs
# 2:	Wed Nov 26 15:25:50 2014 Backdoor started on unix socket /tmp/chainpuller.bd
# log: connect (('127.0.0.1', 8333),)
# downloading headers...
# got 331756 names...
# [BLOCKNUM] (MB/s)
# (0.02)[1000][2000][3000][4000][5000](0.11)[6000][7000][8000][9000][10000]...
# ...[316000][317000](33.41)[318000](33.42)[319000][320000](32.94)[321000](34.02)
# [322000](34.79)[323000][324000](34.31)[325000](33.86)[326000](35.49)[327000]
# (34.11)[328000](33.21)[329000][330000](35.55)[331000](31.43)
# transferred 24.96 GB in 1239 secs (20.62 MB/s)

# Note: on OS X, if you are running bitcoin-qt, it's very important that you keep
#  it in the foreground, otherwise the xfer rate will fall dramatically.

# It's safe to stop and restart this utility.

import argparse

import coro
import time

from caesure.ansi import *
from caesure.connection import BaseConnection, parse_addr_arg
from caesure.global_state import GlobalState
from caesure.proto import unpack_version, unpack_inv, unpack_headers, pack_getblocks
from caesure.bitcoin import *
from caesure.block_db import BlockDB, BLOCK

class ChainPuller (BaseConnection):

    def __init__ (self, G, my_addr, other_addr):
        BaseConnection.__init__ (self, my_addr, other_addr)
        self.waiting = {}

    def wait_for (self, key):
        "wait on a CV with <key> (used by get_block, etc...)"
        if not self.waiting.has_key (key):
            self.waiting[key] = coro.condition_variable()
        try:
            return self.waiting[key].wait()
        finally:
            del self.waiting[key]

    def getheaders (self, hashes=None):
        # on this connection only, download the entire chain of headers from our
        #   tip to the other side's tip.
        if hashes is None:
            hashes = G.block_db.set_for_getblocks()
            if not hashes:
                hashes = [G.genesis_block_hash]
        hashes.append (ZERO_NAME)
        chain = [hashes[0]]
        while 1:
            # getheaders and getblocks have identical args/layout.
            self.send_packet ('getheaders', pack_getblocks (self.version, hashes))
            _, data = coro.with_timeout (30, self.wait_for, 'headers')
            blocks = unpack_headers (data)
            # XXX do some rule checks here to avoid miscreants.
            if len(blocks) == 0:
                break
            else:
                for block in blocks:
                    if block.prev_block == chain[-1]:
                        chain.append (block.name)
                    else:
                        G.log ('getheaders', 'nochain')
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
        block_fifo.push (payload)

    def cmd_tx (self, payload):
        pass

    def cmd_addr (self, payload):
        pass

    def cmd_headers (self, payload):
        pass

MB = 1024 * 1024
GB = 1024 * MB

def go (G):
    global in_flight
    addr0 = ('127.0.0.1', 0)
    addr1 = parse_addr_arg (G.args.connect)
    cp = ChainPuller (G, addr0, addr1)
    cp.wait_for ('verack')
    W ('downloading headers...\n')
    names = cp.getheaders()
    start = time.time()
    W ('got %d names...\n' % (len(names),))
    WB ('[BLOCKNUM] ')
    WR ('(MB/s)\n')
    for i in range (0, len (names), 50):
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
    coro.set_exit()

def write_thread():
    global in_flight, total_bytes
    n = 0
    while 1:
        data = block_fifo.pop()
        b = BLOCK()
        b.unpack (data)
        total_bytes += len(data)
        in_flight -= 1
        if in_flight < G.args.inflight:
            in_flight_cv.wake_all()
        G.block_db.write_block (b.get_name(), b)
        n += 1
        if n % 1000 == 0:
            WB ('[%d]' % (n,))

total_bytes = 0

def rate_thread():
    n0 = 0
    while 1:
        coro.sleep_relative (10)
        n1 = total_bytes
        delta = n1 - n0
        n0 = n1
        WR ('(%.2f)' % (delta / 10485760.))

def log (subject, *data):
    W ('log: %s %r\n' % (subject, data))

G = GlobalState()

p = argparse.ArgumentParser (description='watch for new blocks (and txns with -r).')
p.add_argument ('connect', help="connect to this address", metavar='IP:PORT')
p.add_argument ('-i', '--inflight', type=int, default=20)
p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')

G.args = p.parse_args()
G.args.packet = False
G.log = log
G.verbose = False
G.block_db = BlockDB()

block_fifo = coro.fifo()
# tried to use inverted_semaphore here, couldn't get it to work.
in_flight = 0
in_flight_cv = coro.condition_variable()

import coro.backdoor
coro.spawn (coro.backdoor.serve, unix_path='/tmp/chainpuller.bd')

coro.spawn (go, G)
coro.spawn (rate_thread)
coro.spawn (write_thread)
coro.event_loop()
