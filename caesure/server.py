# -*- Mode: Python -*-

import coro
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
            W ('other_addr=%r\n' % (other_addr,))
            if ':' in other_addr[0]:
                self.conn = coro.tcp6_sock()
            else:
                self.conn = coro.tcp_sock()
        else:
            self.conn = conn
        self.packet_count = 0
        self.stream = coro.read_stream.sock_stream (self.conn)

    def connect (self):
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
                #W ('connection closed.\n')
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

    def get_block (self, name, timeout=5):
        "request a particular block.  return it, or raise TimeoutError"
        self.getdata ([(block_db.OBJ_BLOCK, name)])
        for i in range (5):
            _, data = coro.with_timeout (timeout, self.wait_for, 'block')
            b = block_db.BLOCK()
            b.unpack (data)
            G.hoover.log ('%r got' % (b.name,))
            if b.name == name:
                return b
            else:
                W ('\n[get_block: wrong block? %r != %r]' % (b.name, name))
        raise ValueError

    def get_tx (self, name, timeout=5):
        "request a particular tx.  return it, or raise TimeoutError"
        self.getdata ([(block_db.OBJ_TX, name)])
        for i in range (5):
            _, data = coro.with_timeout (timeout, self.wait_for, 'tx')
            tx = block_db.TX()
            tx.unpack (data)
            if tx.name == name:
                return b

class BadState (Exception):
    pass

class BlockHoover:

    # this class is responsible for downloading the block chain.

    def __init__ (self):
        self.queue = coro.fifo()
        self.qset = set()
        self.qheight = 0
        self.requested = set()
        self.ready = {}
        self.target = 0
        self.running = False
        self.live_cv = coro.condition_variable()
        self.debug = open ('/tmp/hoover.log', 'wb')

    def log (self, msg):
        self.debug.write ('%s %s\n' % (time.ctime(), msg))

    def get_live_connection (self):
        return self.live_cv.wait()

    def notify_height (self, conn, height):
        if height > self.target:
            # XXX sanity check height by calculating a likely neighborhood given the date.
            behind = height - self.target
            self.target = height
            if behind > 10 and not self.running:
                # start hoovering
                coro.spawn (self.go)

    def go (self):
        # main hoovering thread.
        # first, get a list of blocks we need to fetch via getheaders.
        db = G.block_db
        if not db.num_block:
            self.queue.push (block_db.genesis_block_hash)
            self.qset.add (block_db.genesis_block_hash)
        try:
            self.running = True
            c = self.get_live_connection()
            W ('[getheaders start]')
            t0 = block_db.timer()
            names = c.getheaders()
            W ('[getheaders stop %.2f]' % (t0.end(),))
            for name in names:
                self.queue.push (name)
                self.qset.add (name)
            # if relay=False and |connections|=1, this way we get at least one live packet.
            c.ping()
            while len(self.queue):
                if len(self.ready) > 100:
                    names = db.num_block[db.last_block]
                    W ('stalled: names=%r\n' % (names,))
                    self.debug.flush()
                    coro.sleep_relative (1000)
                    stalled = list(names)[0]
                    # where is this in the queue?
                    for j, x in enumerate (self.queue):
                        if x == stalled:
                            W ('found in position %d\n' % (j,))
                            break
                    if x != stalled:
                        W ('not found in queue\n')
                name = self.queue.pop()
                self.log ('%r popped' % (name,))
                self.qset.remove (name)
                c = self.get_live_connection()
                coro.spawn (self.get_block, c, name)
        finally:
            self.running = False

    def get_block (self, conn, name):
        try:
            self.requested.add (name)
            self.log ('%r asked' % (name,))
            self.add_block (conn.get_block (name))
            self.log ('%r received' % (name,))
        except (coro.TimeoutError, ValueError):
            # let some other connection try it...
            W ('[retry %r]' % (name,))
            self.log ('%r retried' % (name,))
            self.queue.push_front (name)
            self.qset.add (name)
            self.requested.remove (name)
        except:
            WY ('\n[get_block: %r]' % (coro.compact_traceback(),))

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

    def block_to_db (self, name, b):
        try:
            b.check_rules()
        except BadState as reason:
            W ('*** bad block: %s %r' % (name, reason))
        else:
            G.block_db.add (name, b)

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
        coro.spawn (self.go)

    def get_our_block_height (self):
        return G.block_db.last_block

    def go (self):
        try:
            if G.connection_map.has_key (self.other_addr):
                W ('duplicate? %r\n' % (self.other_addr,))
                return
            else:
                G.connection_map[self.other_addr] = self
            W ('starting %s connection us: %r them: %r\n' % (self.direction, self.my_addr, self.other_addr))
            try:
                if self.direction == 'outgoing':
                    coro.with_timeout (30, self.connect)
                self.send_version()
                for command, payload in self.gen_packets():
                    self.do_command (command, payload)
                    self.last_packet = coro.now
            except OSError:
                # XXX collect data on errnos
                #W ('OSError: %r\n' % (sys.exc_info()[:2],))
                pass
            except coro.TimeoutError:
                #W ('TimeoutError: %r\n' % (sys.exc_info()[:2],))
                pass
        finally:
            W ('stopping %s connection us: %r them: %r\n' % (self.direction, self.my_addr, self.other_addr))
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

    def wait_for (self, cmd):
        if not self.waiting.has_key (cmd):
            self.waiting[cmd] = coro.condition_variable()
        return self.waiting[cmd].wait()

    def do_command (self, cmd, data):
        if self.waiting.has_key (cmd):
            cv = self.waiting[cmd]
            del self.waiting[cmd]
            cv.wake_all ((cmd, data))
        if self.check_command_name (cmd):
            try:
                method = getattr (self, 'cmd_%s' % cmd,)
            except AttributeError:
                W ('no support for "%s" command\n' % (cmd,))
            else:
                try:
                    method (data)
                except:
                    W ('caesure error: %r\n' % (coro.compact_traceback(),))
                    W ('     ********** problem processing %r command\n' % (cmd,))
        else:
            W ('bad command: "%r", ignoring\n' % (cmd,))

    def cmd_version (self, data):
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
                if kind == block_db.OBJ_BLOCK:
                    if name not in G.block_db:
                        to_fetch.append ((kind, name))
                elif kind == block_db.OBJ_TX:
                    if name not in G.txn_pool:
                        to_fetch.append ((kind, name))
            if to_fetch:
                self.getdata (to_fetch)

    def cmd_getdata (self, data):
        blocks = []
        for kind, name in caesure.proto.unpack_getdata (data):
            if kind == block_db.OBJ_BLOCK and name in G.block_db:
                blocks.append (name)
        coro.spawn (self.send_blocks, blocks)
        
    def send_blocks (self, blocks):
        for name in blocks:
            self.send_packet (
                'block', G.block_db.get_block (name)
            )

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

    def cmd_tx (self, data):
        tx = block_db.TX()
        tx.unpack (data)
        G.txn_pool.add (tx)

    def cmd_block (self, data):
        if not G.hoover.running:
            # normal operation, feed new blocks in
            b = block_db.BLOCK()
            b.unpack (data)
            b.check_rules()
            G.block_db.add (b.name, b)
            # this happens when our last block has been orphaned
            #  by a block that shows up *later* - we need to manually
            #  request the missing link[s].
            if b.prev_block not in G.block_db.blocks:
                self.getdata ([(block_db.OBJ_BLOCK, b.prev_block)])

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
        W ('alert: sig=%r payload=%r\n' % (signature, payload,))

    def cmd_headers (self, data):
        pass

    def send_invs (self, pairs):
        pairs0 = []
        for pair in pairs:
            if pair not in self.known:
                pairs0.append (pair)
        if len(pairs0):
            #W ('{pairs0 = %r}' % (pairs0,))
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
            if len(blocks) == 0:
                break
            else:
                for block in blocks:
                    if block.prev_block == chain[-1]:
                        chain.append (block.name)
                    else:
                        W ('unexpected fork in getheaders from %r\n' % (self,))
                        raise ValueError
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

    save_path = '/usr/local/caesure/peers.bin'

    def save (self):
        pickle.dump (self.cache, open (self.save_path, 'wb'), 2)

    def load (self):
        try:
            self.cache = pickle.load (open (self.save_path, 'rb'))
            W ('loaded %d addresses\n' % (len(self.cache),))
        except IOError:
            self.seed()

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
        W ('seeding via dns...\n')
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

# XXX important - handle txns coming in later that spend outputs that
#   txns in our pool have spent [i.e., double-spends], especially in the
#   case where they are accepted into blocks, we need to know to throw them
#   away.

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
                W ('[tx %064x script failed]' % (tx.name,))
            except KeyError:
                #W ('[tx %064x missing inputs]' % (tx.name,))
                self.missing[tx.name] = tx
        else:
            W ('[tx %064x already]' % (tx.name,))

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
            W (ansi ('[pool: removed %d of %d]' % (in_pool, total), 35))

# --------------------------------------------------------------------------------

def status_thread():
    while 1:
        coro.sleep_relative (10)
        coro.write_stderr (
            '[clients:%d addr_cache:%d]\n' % (
                len(G.connection_map),
                len(G.addr_cache.cache),
            )
        )

def new_block_thread():
    while 1:
        block = G.block_db.new_block_cv.wait()
        name = block.name
        nsent = 0
        if not G.hoover.running:
            for c in G.connection_map.values():
                if c.packet_count:
                    try:
                        c.send_invs ([(block_db.OBJ_BLOCK, name)])
                        nsent += 1
                    except OSError:
                        # let the gen_packets loop deal with this.
                        pass
        #G.txmap.feed_block (block, block.get_height())
        G.recent_blocks.new_block (block)
        W ('[new_block %d]' % (nsent,))

def new_connection_thread():
    # give the servers time to start up and set addresses
    coro.sleep_relative (2)
    while 1:
        G.out_conn_sem.acquire (1)
        addr1 = new_random_addr()
        addr0 = get_my_addr (addr1)
        Connection (addr0, addr1)
        # avoid hammering the internets
        coro.sleep_relative (1)

def new_random_addr():
    for i in range (100):
        (ip, port) = G.addr_cache.random()
        if (ip, port) not in G.connection_map:
            if ip == '192.33.90.253':
                # filter out eth switzerland (they comprise 25% of all addrs).
                pass
            else:
                return (ip, port)

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

def go (args, global_state):
    global G
    G = global_state
    G.args = args
    G.addr_cache = AddressCache()
    G.block_db = block_db.BlockDB (read_only=False)
    G.hoover = BlockHoover()
    G.txn_pool = TransactionPool()
    G.recent_blocks = ledger.catch_up (G)
    G.verbose = args.verbose
    G.connection_map = {}

    # needed for the sub-imports below...
    import coro
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
    #coro.spawn (status_thread)
    coro.spawn (G.addr_cache.purge_thread)
    coro.spawn (new_block_thread)
    coro.spawn (new_connection_thread)
    coro.spawn (G.recent_blocks.save_ledger_thread)
