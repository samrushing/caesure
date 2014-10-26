# -*- Mode: Python -*-

import coro
import os
import pickle
import random
import re
import string
import struct
import sys
import time
from pprint import pprint as pp

from caesure import block_db
from caesure import ledger
from caesure import proto
from caesure import script
from caesure.bitcoin import *
from caesure.ansi import *
from caesure.asn1_log import ASN1_Logger

ticks_to_sec = coro.tsc_time.ticks_to_sec

# really need that pattern match compiler!
# ipv4 not routable:
# [10, ...]
# [192, 168, ...]
# [172, 16, ...]
# [169, 254, ...]
# ipv6 not routable
# [0xfc, ...] # unique local
# [0xfd, ...] # unique local
# [0xfe, 0x80, ...], # (e.g. link) local

def is_routable (addr):
    SW = addr.startswith
    if ':' in addr:
        return not (addr == '::1' or SW ('fc') or SW ('fd') or SW ('fe80:'))
    else:
        return not (
            SW ('127.') or SW ('255.') or SW ('0.') or SW ('10.')
            or SW ('192.168.') or SW ('172.16.') or SW ('169.254')
        )

def secs_since (t0):
    return float (coro.now - t0) / coro.ticks_per_sec

def get_random_connection():
    "get a random live connection"
    conns = []
    for addr, c in G.connection_map.iteritems():
        if secs_since (c.last_packet) < 30:
            conns.append (c)
    if len(conns):
        return random.choice (conns)
    else:
        return None

# May 2014 fetched from https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
dns_seeds = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    # down?
    #"dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitnodes.io",
    "bitseed.xf2.org",
]

def make_nonce():
    return random.randint (0, 1 << 64)

class BaseConnection:

    # protocol version
    version = 70001
    # software version
    version_string = '/caesure:20141014/'
    # relay flag (see bip37 for details...)
    relay = False

    def __init__ (self, my_addr, other_addr, conn=None):
        self.my_addr = my_addr
        self.other_addr = other_addr
        self.nonce = make_nonce()
        self.other_version = None
        self.send_mutex = coro.mutex()
        if conn is None:
            if ':' in other_addr[0]:
                self.conn = coro.tcp6_sock()
            else:
                self.conn = coro.tcp_sock()
        else:
            self.conn = conn
        self.packet_count = 0
        self.stream = coro.read_stream.sock_stream (self.conn)

    def connect (self):
        G.log ('connect', self.other_addr)
        self.conn.connect (self.other_addr)

    def send_packet (self, command, payload):
        with self.send_mutex:
            lc = len(command)
            assert (lc < 12)
            cmd = command + ('\x00' * (12 - lc))
            h = dhash (payload)
            checksum, = struct.unpack ('<I', h[:4])
            self.conn.writev ([
                block_db.MAGIC,
                cmd,
                struct.pack ('<II', len(payload), checksum),
                payload
            ])
            if G.args.packet:
                G.log ('send', self.other_addr, command, payload)
            if G.verbose and command not in ('ping', 'pong'):
                WT (' ' + command)

    def get_our_block_height (self):
        return G.block_db.last_block

    def send_version (self):
        v = caesure.proto.VERSION()
        v.version = self.version
        v.services = 1
        v.timestamp = int(time.time())
        v.you_addr = (1, self.other_addr)
        v.me_addr = (1, self.my_addr)
        v.nonce = self.nonce
        v.sub_version_num = self.version_string
        start_height = self.get_our_block_height()
        if start_height < 0:
            start_height = 0
        v.start_height = start_height
        v.relay = self.relay
        self.send_packet ('version', v.pack())

    def gen_packets (self):
        while 1:
            data = self.stream.read_exact (24)
            if not data:
                G.log ('closed', self.other_addr)
                break
            magic, command, length, checksum = struct.unpack ('<I12sII', data)
            command = command.strip ('\x00')
            if G.verbose and command not in ('ping', 'pong'):
                WF (' ' + command)
            self.packet_count += 1
            self.header = magic, command, length
            # XXX need timeout here for DoS
            if length:
                payload = self.stream.read_exact (length)
            else:
                payload = ''
            if G.args.packet:
                G.log ('recv', self.other_addr, command, payload)
            G.hoover.live_cv.wake_one (self)
            yield (command, payload)

    def getblocks (self):
        hashes = G.block_db.set_for_getblocks()
        hashes.append (block_db.ZERO_NAME)
        self.send_packet ('getblocks', caesure.proto.pack_getblocks (self.version, hashes))

    def getdata (self, items):
        "request (TX|BLOCK)+ from the other side"
        # note: pack_getdata == pack_inv
        self.send_packet ('getdata', caesure.proto.pack_inv (items))

class BadState (Exception):
    pass

class BlockHoover:

    # this class is responsible for downloading the block chain.

    def __init__ (self, in_flight=20):
        self.queue = coro.fifo()
        self.qset = set()
        self.requested = set()
        self.ready = {}
        self.target = G.block_db.last_block
        self.running = False
        self.live_cv = coro.condition_variable()
        self.in_flight_sem = coro.semaphore (in_flight)

    def get_live_connection (self):
        return self.live_cv.wait()

    def notify_height (self, conn, height):
        if height > self.target:
            # XXX sanity check height by calculating a likely neighborhood given the date.
            behind = height - self.target
            self.target = height
            if not self.running:
                # start hoovering
                coro.spawn (self.go, conn)

    def push (self, name):
        self.queue.push (name)
        self.qset.add (name)

    def go (self, c):
        # main hoovering thread.
        # first, get a list of blocks we need to fetch via getheaders.
        db = G.block_db
        if not db.num_block:
            self.push (block_db.genesis_block_hash)
        try:
            self.running = True
            # get the list of all blocks we need to fetch...
            G.log ('getheaders', 'start')
            t0 = block_db.timer()
            names = c.getheaders()
            G.log ('getheaders', 'stop', '%.02f' % t0.end())
            if names:
                # start fetching them...
                coro.spawn (self.drain_queue_thread)
                for name in names:
                    self.in_flight_sem.acquire(1)
                    self.push (name)
                self.queue.push (None)
        finally:
            self.running = False

    def drain_queue_thread (self):
        while 1:
            name = self.queue.pop()
            if name is None:
                break
            else:
                G.log ('hoover', 'popped', str(name))
                self.qset.remove (name)
                c = self.get_live_connection()
                coro.spawn (self.get_block, c, name)

    def get_block (self, conn, name):
        try:
            self.requested.add (name)
            strname = str(name)
            t0 = coro.now_usec
            G.log ('hoover', 'asked', strname)
            self.add_block (conn.get_block (name))
            G.log ('hoover', 'recv', strname)
            self.in_flight_sem.release(1)
        except coro.TimeoutError:
            # let some other connection try it...
            G.log ('hoover', 'retry', strname)
            self.push (name)
            self.requested.remove (name)
        except:
            G.log ('hoover', 'error', coro.compact_traceback())

    def add_block (self, b):
        self.ready[b.prev_block] = b
        if b.name in self.requested:
            self.requested.remove (b.name)
        # we may have several blocks waiting to be chained
        #  in by the arrival of a missing link...
        while 1:
            if G.block_db.has_key (b.prev_block) or (b.prev_block == block_db.ZERO_NAME):
                del self.ready[b.prev_block]
                self.block_to_db (b.name, b)
                if self.ready.has_key (b.name):
                    b = self.ready[b.name]
                else:
                    break
            else:
                break
            coro.yield_slice()

    def block_to_db (self, name, b):
        try:
            b.check_rules()
        except BadState as reason:
            G.log ('block_to_db', 'bad block', str(name), reason)
        else:
            G.block_db.add (name, b)
            G.recent_blocks.new_block (b)

class Connection (BaseConnection):

    relay = False

    def __init__ (self, my_addr, other_addr, sock=None):
        BaseConnection.__init__ (self, my_addr, other_addr, sock)
        self.last_packet = 0
        if sock is not None:
            self.direction = 'incoming'
        else:
            self.direction = 'outgoing'
        self.waiting = {}
        self.known = set()
        self.kick_download = None
        coro.spawn (self.go)

    def get_our_block_height (self):
        return G.block_db.last_block

    def go (self):
        try:
            if G.connection_map.has_key (self.other_addr):
                return
            else:
                G.connection_map[self.other_addr] = self
            G.log ('connect', self.direction, self.my_addr, self.other_addr)
            try:
                if self.direction == 'outgoing':
                    coro.with_timeout (30, self.connect)
                self.send_version()
                for command, payload in self.gen_packets():
                    self.do_command (command, payload)
                    self.last_packet = coro.now
            except OSError:
                # XXX collect data on errnos
                G.log ('connection', 'oserror', self.other_addr)
            except coro.TimeoutError:
                G.log ('connection', 'timeout', self.other_addr)
        finally:
            G.log ('stopped', self.direction, self.my_addr, self.other_addr)
            del G.connection_map[self.other_addr]
            if self.direction == 'incoming':
                G.in_conn_sem.release (1)
            else:
                G.out_conn_sem.release (1)

    def check_command_name (self, command):
        for ch in command:
            if ch not in string.letters:
                return False
        return True

    def wait_for (self, key):
        "wait on a CV with <key> (used by get_block, etc...)"
        if not self.waiting.has_key (key):
            self.waiting[key] = coro.condition_variable()
        try:
            return self.waiting[key].wait()
        finally:
            del self.waiting[key]

    def get_block (self, name, timeout=10):
        "request a particular block.  return it, or raise TimeoutError"
        key = (OBJ_BLOCK, name)
        self.getdata ([key])
        return coro.with_timeout (timeout, self.wait_for, key)

    def get_tx (self, name, timeout=10):
        "request a particular tx.  return it, or raise TimeoutError"
        key = (OBJ_BLOCK, name)
        self.getdata ([key])
        return coro.with_timeout (timeout, self.wait_for, key)

    def do_command (self, cmd, data):
        if self.waiting.has_key (cmd):
            self.waiting[cmd].wake_all ((cmd, data))
        if self.check_command_name (cmd):
            try:
                method = getattr (self, 'cmd_%s' % cmd,)
            except AttributeError:
                G.log ('connection', 'unknown_command', cmd)
            else:
                try:
                    method (data)
                except:
                    G.log ('connection', 'error', cmd, coro.compact_traceback())
        else:
            G.log ('connection', 'bad_command', cmd)

    def cmd_version (self, data):
        # XXX sanity check this data
        G.log ('version', data)
        self.other_version = caesure.proto.unpack_version (data)
        self.send_packet ('verack', '')
        G.hoover.notify_height (self, self.other_version.start_height)

    def cmd_verack (self, data):
        pass

    def cmd_addr (self, data):
        for timestamp, entry in caesure.proto.unpack_addr (data):
            G.addr_cache.add (timestamp, entry)

    def cmd_inv (self, data):
        pairs = caesure.proto.unpack_inv (data)
        for pair in pairs:
            self.known.add (pair)
        if not G.hoover.running:
            to_fetch = []
            for kind, name in pairs:
                if kind == OBJ_BLOCK:
                    if name not in G.block_db:
                        to_fetch.append ((kind, name))
                elif kind == OBJ_TX:
                    if name not in G.txn_pool:
                        to_fetch.append ((kind, name))
            if to_fetch:
                self.getdata (to_fetch)

    def get_next_500 (self, start_name, stop_name):
        db = G.block_db
        height = db.block_num[start_name]
        height = min (db.last_block, height + 500)
        W ('walking backward from height %d\n' % (height,))
        # find an uncontested starting point
        while 1:
            names = db.num_block[height]
            if len(names) == 1:
                break
            else:
                height -= 1
        # from there, walk the main chain backward
        name = list(names)[0]
        #W ('walking backward from %r\n' % (name,))
        r = []
        while name != start_name and name != stop_name:
            r.append ((OBJ_BLOCK, name))
            name = db.prev[name]
        # put the names in forward order...
        r.reverse()
        #W ('done: %d names\n' % (len(r),))
        return r

    def cmd_getblocks (self, data):
        version, names = caesure.proto.unpack_getblocks (data)
        #W ('\ncmd_getblocks: names=%r\n' % (names,))
        hash_stop = names[-1]
        db = G.block_db
        found = None
        for name in names:
            if db.has_key (name):
                found = name
                break
        #W ('found=%r\n' % (found,))
        if found:
            name = found
            invs = self.get_next_500 (name, hash_stop)
            #self.send_invs (invs)
            # send without filtering, we're getting some kind of getblocks
            #   wild failure mode otherwise...
            self.send_packet ('inv', caesure.proto.pack_inv ([]))
            if invs:
                self.kick_download = invs[-1][1]

    def cmd_getdata (self, data):
        blocks = []
        for kind, name in caesure.proto.unpack_getdata (data):
            if kind == OBJ_BLOCK and name in G.block_db:
                blocks.append (name)
        coro.spawn (self.send_blocks, blocks)
        
    def send_blocks (self, blocks):
        for name in blocks:
            self.send_packet (
                'block', G.block_db.get_block (name)
            )
            if name == self.kick_download:
                # this is a horrible hack to smack old bitcoin core into continuing
                #   a blockchain download.
                self.kick_download = None
                db = G.block_db
                last_name = list(db.num_block[db.last_block])[0]
                key = (OBJ_BLOCK, last_name)
                try:
                    self.known.remove (key)
                except KeyError:
                    pass
                self.send_invs ([key])
                W ('sent kick for %r\n' % (last_name,))

    def cmd_getaddr (self, data):
        # XXX we should have a thread do this once a minute or so, precomputed.
        # get our list of active peers
        three_hours = 3 * 60 * 60
        r = []
        nodes = G.connection_map.values()
        random.shuffle (nodes)
        for v in nodes:
            if v is not self and secs_since (v.last_packet) < three_hours:
                r.append ((
                    ticks_to_sec (v.last_packet),
                    (v.other_version.services, v.other_addr)
                ))
            # cap it at 100 addresses
            if len(r) >= 100:
                break
        payload = caesure.proto.pack_addr (r)
        self.send_packet ('addr', payload)

    def maybe_wake (self, key, ob):
        probe = self.waiting.get (key, None)
        if probe is not None:
            probe.wake_all (ob)

    def cmd_tx (self, data):
        tx = block_db.TX()
        tx.unpack (data)
        self.maybe_wake ((OBJ_TX, tx.name), tx)
        G.txn_pool.add (tx)

    def cmd_block (self, data):
        b = block_db.BLOCK()
        b.unpack (data)
        key = (OBJ_BLOCK, b.name)
        self.known.add (key)
        self.maybe_wake (key, b)
        if not G.hoover.running:
            # normal operation, feed new blocks in
            b.check_rules()
            # XXX once we have txn verification slotted in, sketch out
            #     exact rules for notifying, writing to disk, etc...
            G.block_db.add (b.name, b)
            # this happens when our last block has been orphaned
            #  by a block that shows up *later* - we need to manually
            #  request the missing link[s].
            if b.prev_block not in G.block_db.blocks:
                self.getdata ([(OBJ_BLOCK, b.prev_block)])

    def cmd_notfound (self, data):
        # XXX need to use this in hoover.wait_for!
        pass

    def cmd_ping (self, data):
        self.send_packet ('pong', data)

    def cmd_pong (self, data):
        pass

    def ping (self):
        nonce = struct.pack ('>Q', make_nonce())
        self.send_packet ('ping', nonce)
        _, data = coro.with_timeout (10, self.wait_for, 'pong')
        assert (nonce == data)

    def cmd_alert (self, data):
        payload, signature = caesure.proto.unpack_alert (data)
        # XXX verify signature
        G.log ('alert', signature, payload)

    def cmd_headers (self, data):
        pass

    def send_invs (self, pairs):
        pairs0 = []
        for pair in pairs:
            if pair not in self.known:
                pairs0.append (pair)
        if len(pairs0):
            self.send_packet ('inv', caesure.proto.pack_inv (pairs0))
            self.known.update (pairs0)

    def test_gh (self, back):
        db = G.block_db
        save, db.last_block = db.last_block, db.last_block - back
        hashes = G.block_db.set_for_getblocks()
        db.last_block = save
        return self.getheaders (hashes)

    def getheaders (self, hashes=None):
        # on this connection only, download the entire chain of headers from our
        #   tip to the other side's tip.
        if hashes is None:
            hashes = G.block_db.set_for_getblocks()
            if not hashes:
                hashes = [block_db.genesis_block_hash]
        hashes.append (block_db.ZERO_NAME)
        chain = [hashes[0]]
        while 1:
            # getheaders and getblocks have identical args/layout.
            self.send_packet ('getheaders', caesure.proto.pack_getblocks (self.version, hashes))
            _, data = coro.with_timeout (30, self.wait_for, 'headers')
            blocks = caesure.proto.unpack_headers (data)
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
        # we already have chain[0]
        return chain[1:]

class AddressCache:

    def __init__ (self):
        self.cache = {}
        self.load()

    def add (self, timestamp, entry):
        # each entry consists of (services, (addr, port))
        (services, (ip, port)) = entry
        if is_routable (ip):
            self.cache[(ip, port)] = (timestamp, services)

    save_path = 'peers.bin'

    def save (self):
        from __main__ import G
        save_path = os.path.join (G.args.base, self.save_path)
        pickle.dump (self.cache, open (save_path, 'wb'), 2)

    def load (self):
        from __main__ import G
        save_path = os.path.join (G.args.base, self.save_path)
        try:
            self.cache = pickle.load (open (save_path, 'rb'))
            G.log ('address-cache', 'load', len(self.cache))
        except IOError:
            self.seed()

    def __len__ (self):
        return len(self.cache)

    def random (self):
        return random.choice (self.cache.keys())

    def purge (self):
        now = coro.tsc_time.now_raw_posix_sec()
        keys = self.cache.keys()
        for key in keys:
            timestamp, services = self.cache[key]
            if (now - timestamp) > (3 * 60 * 60):
                del self.cache[key]

    def purge_thread (self):
        while 1:
            coro.sleep_relative (5 * 61)
            self.purge()
            self.save()

    def seed (self):
        # called only when we don't have a cached peer set.
        G.log ('dns', 'seeding...')
        timestamp = coro.tsc_time.now_raw_posix_sec()
        r = coro.get_resolver()
        addrs = set()
        for seed in dns_seeds:
            try:
                for (t, ip) in r.cache.query (seed, 'A'):
                    self.add (timestamp, (1, (ip, 8333)))
                for (t, ip) in r.cache.query (seed, 'AAAA'):
                    self.add (timestamp, (1, (ip, 8333)))
            except coro.dns.exceptions.DNS_Soft_Error:
                pass

# --------------------------------------------------------------------------------

# XXX This is just a placeholder for now.  I'm fairly certain that we'll need
#   a different pool for each ledger tip, and we'll probably need to have a
#   modified version of that block's outpoints as well.  This class [or a version
#   will probably move to the ledger module].

class TransactionPool:

    def __init__ (self):
        self.missing = {}
        self.pool = {}
        coro.spawn (self.new_block_thread)

    def __contains__ (self, name):
        return name in self.pool

    def add (self, tx):
        W ('TransactionPool.add() called and ignored\n')
        return 
        if tx.name not in self.pool:
            try:
                i = 0
                for outpoint, oscript, sequence in tx.inputs:
                    amt, redeem = G.txmap[outpoint]
                    tx.verify0 (i, redeem)
                    i += 1
                self.pool[tx.name] = tx
            except script.ScriptFailure:
                G.log ('pool', 'script failure', str(tx.name))
            except KeyError:
                G.log ('pool', 'missing inputs', str(tx.name))
                self.missing[tx.name] = tx
        else:
            G.log ('pool', 'already', str(tx.name))

    def new_block_thread (self):
        while 1:
            b = G.block_db.new_block_cv.wait()
            in_pool = 0
            total = len(self.pool)
            for tx in b.transactions:
                try:
                    del self.pool[tx.name]
                    in_pool += 1
                except KeyError:
                    pass
            G.log ('pool', 'removed', in_pool, total)

# --------------------------------------------------------------------------------

def new_block_thread():
    while 1:
        block = G.block_db.new_block_cv.wait()
        name = block.name
        G.log ('block', str(block.name))
        G.recent_blocks.new_block (block)
        if not G.hoover.running:
            nsent = 0
            for c in G.connection_map.values():
                if c.packet_count:
                    try:
                        c.send_invs ([(OBJ_BLOCK, name)])
                        nsent += 1
                    except OSError:
                        # let the gen_packets loop deal with this.
                        pass

def new_connection_thread():
    # give the servers time to start up and set addresses
    coro.sleep_relative (2)
    while 1:
        addr1 = new_random_addr()
        if addr1 is not None:
            G.out_conn_sem.acquire (1)
            addr0 = get_my_addr (addr1)
            Connection (addr0, addr1)
        # avoid hammering the internets
        coro.sleep_relative (1)

def new_random_addr():
    if len(G.addr_cache):
        for i in range (100):
            (ip, port) = G.addr_cache.random()
            if (ip, port) not in G.connection_map:
                if ip == '192.33.90.253':
                    # filter out eth switzerland (they comprise 25% of all addrs).
                    pass
                else:
                    return (ip, port)
    else:
        return None

ipv4_server_addrs = []
ipv6_server_addrs = []

ipv6_server_re = re.compile ('\[([A-Fa-f0-9:]+)\]:([0-9]+)')
ipv4_server_re = re.compile ('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)')

def parse_addr_arg (addr):
    m = ipv4_server_re.match (addr)
    if not m:
        m = ipv6_server_re.match (addr)
        if not m:
            raise ValueError ("bad server address: %r" % (addr,))
    ip0, port0 = m.groups()
    port0 = int (port0)
    addr0 = (ip0, port0)
    return addr0

def serve (addr):
    addr0 = parse_addr_arg (addr)
    if ':' in addr0[0]:
        ipv6_server_addrs.append (addr0)
        s = coro.tcp6_sock()
    else:
        ipv4_server_addrs.append (addr0)
        s = coro.tcp_sock()
    s.bind (addr0)
    s.listen (100)
    W ('starting server on %r\n' % (addr0,))
    G.log ('server', 'start', addr0)
    while 1:
        conn, addr1 = s.accept()
        G.in_conn_sem.acquire (1)
        Connection (addr0, addr1, sock=conn)

def get_my_addr (other):
    if ':' in other[0]:
        if len(ipv6_server_addrs):
            return random.choice (ipv6_server_addrs)
        else:
            return ('::1', 8333)
    else:
        if len(ipv4_server_addrs):
            return random.choice (ipv4_server_addrs)
        else:
            return ('127.0.0.1', 8333)

def connect (addr):
    addr1 = parse_addr_arg (addr)
    G.out_conn_sem.acquire (1)
    addr0 = get_my_addr (addr1)
    Connection (addr0, addr1)

def exception_notifier():
    me = coro.current()
    traceback = coro.compact_traceback()
    G.log ('exception', me.id, me.name, traceback)
    WY ('exception: %r %r %r\n' % (me.id, me.name, traceback))

def go (args, global_state):
    global G
    G = global_state
    G.args = args
    G.logger = ASN1_Logger (
        open (os.path.join (G.args.base, 'log.asn1'), 'ab')
        )
    G.log = G.logger.log
    # needed for the sub-imports below...
    import coro
    coro.set_exception_notifier (exception_notifier)
    G.log ('starting caesure')
    G.addr_cache = AddressCache()
    G.block_db = block_db.BlockDB (read_only=False)
    G.hoover = BlockHoover()
    G.txn_pool = TransactionPool()
    G.recent_blocks = ledger.catch_up (G)
    G.verbose = args.verbose
    G.connection_map = {}
    # install a real resolver
    coro.dns.cache.install()
    if args.monitor:
        import coro.backdoor
        coro.spawn (coro.backdoor.serve, unix_path='/tmp/caesure.bd')
    users = {}
    if args.user:
        for user in args.user:
            u, p = user.split (':')
            users[u] = p
    if args.webui:
        import coro.http
        import caesure.webadmin
        import zlib
        G.http_server = h = coro.http.server()
        G.webadmin_handler = caesure.webadmin.handler (G)
        if users:
            h.push_handler (coro.http.handlers.auth_handler (users, G.webadmin_handler))
            coro.spawn (h.start, (('', 8380)))
        else:
            h.push_handler (G.webadmin_handler)
            coro.spawn (h.start, (('127.0.0.1', 8380)))
        h.push_handler (coro.http.handlers.coro_status_handler())
        h.push_handler (
            coro.http.handlers.favicon_handler (
                zlib.compress (caesure.webadmin.favicon)
            )
        )
    G.in_conn_sem = coro.semaphore (args.incoming)
    G.out_conn_sem = coro.semaphore (args.outgoing)
    if args.relay:
        Connection.relay = True
    if args.serve:
        for addr in args.serve:
            coro.spawn (serve, addr)
    if args.connect:
        for addr in args.connect:
            coro.spawn (connect, addr)
    coro.spawn (G.addr_cache.purge_thread)
    coro.spawn (new_block_thread)
    coro.spawn (new_connection_thread)
    coro.spawn (G.recent_blocks.save_ledger_thread)
