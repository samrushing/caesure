#!/usr/bin/env python
# -*- Mode: Python; indent-tabs-mode: nil -*-

import argparse

import coro

from caesure.ansi import *
from caesure.connection import BaseConnection, parse_addr_arg
from caesure.global_state import GlobalState
from caesure.proto import unpack_version, unpack_inv
from caesure.bitcoin import *

class BlockWatcher (BaseConnection):

    def __init__ (self, G, my_addr, other_addr):
        BaseConnection.__init__ (self, my_addr, other_addr)
        self.seen_blocks = set()
        self.seen_txns = set()
        if G.args.txns:
            self.relay = True

    def cmd_inv (self, data):
        pairs = unpack_inv (data)
        to_fetch = []
        for kind, name in pairs:
            if kind == OBJ_BLOCK:
                if name not in self.seen_blocks:
                    to_fetch.append ((kind, name))
            elif kind == OBJ_TX:
                if name not in self.seen_txns:
                    to_fetch.append ((kind, name))
        if to_fetch:
            self.getdata (to_fetch)

    def cmd_block (self, payload):
        b = BLOCK()
        b.unpack (payload)
        self.seen_blocks.add (b.name)
        sys.stdout.write ('----- block -----\n')
        b.dump (sys.stdout)

    def cmd_tx (self, payload):
        tx = TX()
        tx.unpack (payload)
        self.seen_txns.add (tx.name)
        sys.stdout.write ('----- tx -----\n')
        tx.dump (sys.stdout)

    def cmd_addr (self, payload):
        pass

def connect (G, addr):
    addr0 = ('127.0.0.1', 0)
    addr1 = parse_addr_arg (addr)
    BlockWatcher (G, addr0, addr1)
    W ('connect() called\n')

def go (G):
    for addr in G.args.connect:
        coro.spawn (connect, G, addr)

def log (subject, *data):
    W ('log: %s %r\n' % (subject, data))

G = GlobalState()

p = argparse.ArgumentParser (description='watch for new blocks (and txns with -t).')
p.add_argument ('connect', action="append", help="connect to this address", metavar='IP:PORT')
p.add_argument ('-v', '--verbose', action='store_true', help='show verbose packet flow')
p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
p.add_argument ('-t', '--txns', action='store_true', help='watch for txns too', default=False)

G.args = p.parse_args()
G.args.packet = False
G.log = log
G.verbose = G.args.verbose

coro.spawn (go, G)
coro.event_loop()
