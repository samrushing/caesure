# -*- Mode: Python -*-

import bitcoin
import coro
import pickle
import random
import re
import string
import struct
import sys
import time
from pprint import pprint as pp

from bitcoin import dhash
import caesure.proto

from caesure.proto import Name

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

W = coro.write_stderr

the_connection_map = {}
the_block_db = None

def get_random_connection():
    "get a random live connection"
    conns = []
    for addr, c in the_connection_map.iteritems():
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

    def __init__ (self, my_addr, other_addr, conn=None):
        self.my_addr = my_addr
        self.other_addr = other_addr
        self.nonce = make_nonce()
        self.other_version = None
        # see bip37 for details...
        self.relay = True
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
        lc = len(command)
        assert (lc < 12)
        cmd = command + ('\x00' * (12 - lc))
        h = dhash (payload)
        checksum, = struct.unpack ('<I', h[:4])
        self.conn.writev ([
            bitcoin.MAGIC,
            cmd,
            struct.pack ('<II', len(payload), checksum),
            payload
        ])
        W ('>%s>' % (command,))

    def get_our_block_height (self):
        return the_block_db.last_block

    version_string = '/caesure:20140422/'

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
                W ('connection closed.\n')
                break
            magic, command, length, checksum = struct.unpack ('<I12sII', data)
            command = command.strip ('\x00')
            W ('[%s]' % (command,))
            self.packet_count += 1
            self.header = magic, command, length
            # XXX need timeout here for DoS
            if length:
                payload = self.stream.read_exact (length)
            else:
                payload = ''
            the_hoover.live_cv.wake_one (self)
            yield (command, payload)

    def getblocks (self):
        hashes = the_block_db.set_for_getblocks()
        hashes.append (bitcoin.ZERO_NAME)
        self.send_packet ('getblocks', caesure.proto.pack_getblocks (self.version, hashes))

    def getdata (self, items):
        "request (TX|BLOCK)+ from the other side"
        W ('GD%d ' % (len(items),))
        self.send_packet ('getdata', caesure.proto.pack_getdata (items))

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

    def get_live_connection (self):
        return self.live_cv.wait()

    def notify_height (self, conn, height):
        if height > self.target:
            # XXX sanity check height by calculating a likely neighborhood given the date.
            behind = height - self.target
            self.target = height
            if behind > 10 and not self.running:
                # start the getblocks thread
                coro.spawn (self.go)

    def go (self):
        # main hoovering thread.
        try:
            self.running = True
            while the_block_db.last_block < self.target:
                W ('{hoover0}')
                if len(self.queue) == 0:
                    self.getblocks()
                if len(self.queue) == 0:
                    break
                else:
                    # self.queue is non-empty, start requesting blocks (in groups of ? at a time)
                    while len(self.queue) and the_block_db.last_block < self.target:
                        W ('{hoover1}')
                        name = self.queue.pop()
                        self.qset.remove (name)
                        c = self.get_live_connection()
                        self.requested.add (name)
                        coro.spawn (self.get_block, c, name)
        finally:
            self.running = False

    def getblocks (self):
        # add to our queue of blocks to fetch
        while 1:
            W ('{getblocks}')
            c = self.get_live_connection()
            c.getblocks()
            # wait til we get the response we want
            try:
                _, data = coro.with_timeout (30, c.wait_for, 'inv')
                pairs = caesure.proto.unpack_inv (data)
                if len(pairs) and all (x[0] == bitcoin.OBJ_BLOCK for x in pairs):
                    # yup, that's what we were waiting for...
                    for _, name in pairs:
                        if name not in self.qset and name not in the_block_db.blocks:
                            self.queue.push (name)
                            self.qset.add (name)
                    return
            except coro.TimeoutError:
                pass

    def get_block (self, conn, name):
        # request the block we need...
        conn.getdata ([(bitcoin.OBJ_BLOCK, name)])
        while 1:
            W ('{get_block}')
            # wait til we get the response we want
            try:
                _, data = coro.with_timeout (30, conn.wait_for, 'block')
                b = bitcoin.BLOCK()
                b.unpack (data)
                if b.name == name:
                    # yup, that's the one we wanted...
                    self.add_block (b)
                    return
            except coro.TimeoutError:
                # let some other connection try it...
                self.queue.push_front (name)
                self.qset.add (name)
                return

    def add_block (self, b):
        self.ready[b.prev_block] = b
        if b.name in self.requested:
            self.requested.remove (b.name)
        # we may have several blocks waiting to be chained
        #  in by the arrival of a missing link...
        while 1:
            if the_block_db.has_key (b.prev_block) or (b.prev_block == bitcoin.ZERO_NAME):
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
            the_block_db.add (name, b)

class Connection (BaseConnection):

    version_string = '/caesure:20140523/'

    def __init__ (self, my_addr, other_addr, sock=None):
        BaseConnection.__init__ (self, my_addr, other_addr, sock)
        self.relay = False
        self.last_packet = 0
        if sock is not None:
            self.direction = 'incoming'
        else:
            self.direction = 'outgoing'
        self.waiting = {}
        coro.spawn (self.go)

    def get_our_block_height (self):
        return the_block_db.last_block

    def go (self):
        try:
            if the_connection_map.has_key (self.other_addr):
                W ('duplicate? %r\n' % (self.other_addr,))
                return
            else:
                the_connection_map[self.other_addr] = self
            W ('starting %s connection us: %r them: %r\n' % (self.direction, self.my_addr, self.other_addr))
            try:
                if self.direction == 'outgoing':
                    self.connect()
                self.send_version()
                for command, payload in self.gen_packets():
                    self.do_command (command, payload)
                    self.last_packet = coro.now
            except OSError:
                # XXX collect data on errnos
                W ('OSError: %r\n' % (sys.exc_info()[:2],))
                pass
        finally:
            W ('stopping %s connection us: %r them: %r\n' % (self.direction, self.my_addr, self.other_addr))
            del the_connection_map[self.other_addr]
            if self.direction == 'incoming':
                in_conn_sem.release (1)
            else:
                out_conn_sem.release (1)

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
        the_hoover.notify_height (self, self.other_version.start_height)

    def cmd_verack (self, data):
        pass

    def cmd_addr (self, data):
        for timestamp, entry in caesure.proto.unpack_addr (data):
            the_addr_cache.add (timestamp, entry)

    def cmd_inv (self, data):
        pairs = caesure.proto.unpack_inv (data)
        if not the_hoover.running:
            to_fetch = []
            for kind, name in pairs:
                if kind == bitcoin.OBJ_BLOCK:
                    if not the_block_db.has_key (name):
                        to_fetch.append ((kind, name))
            if to_fetch:
                self.getdata (to_fetch)

    def cmd_getdata (self, data):
        return caesure.proto.unpack_getdata (data)

    def cmd_getaddr (self, data):
        # XXX we should have a thread do this once a minute or so, precomputed.
        # get our list of active peers
        three_hours = 3 * 60 * 60
        r = []
        nodes = the_connection_map.values()
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
        W ('addr payload=%s\n' % (payload.encode ('hex')))
        self.send_packet ('addr', payload)

    def cmd_tx (self, data):
        return caesure.proto.make_tx (data)

    def cmd_block (self, data):
        if not the_hoover.running:
            # normal operation, feed new blocks in
            b = bitcoin.BLOCK()
            b.unpack (data)
            b.check_rules()
            the_block_db.add (b.name, b)

    def cmd_notfound (self, data):
        # XXX need to use this in hoover.wait_for!
        pass

    def cmd_ping (self, data):
        W ('ping: data=%r\n' % (data,))
        self.send_packet ('pong', data)

    def cmd_alert (self, data):
        payload, signature = caesure.proto.unpack_alert (data)
        # XXX verify signature
        W ('alert: sig=%r payload=%r\n' % (signature, payload,))

class AddressCache:

    def __init__ (self):
        self.cache = {}
        self.load()

    def add (self, timestamp, entry):
        # each entry consists of (services, (addr, port))
        (services, (ip, port)) = entry
        if is_routable (ip):
            self.cache[(ip, port)] = (timestamp, services)

    def save (self):
        pickle.dump (self.cache, open ('peers.bin', 'wb'), 2)

    def load (self):
        try:
            self.cache = pickle.load (open ('peers.bin', 'rb'))
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

def status_thread():
    while 1:
        coro.sleep_relative (10)
        coro.write_stderr (
            '[clients:%d addr_cache:%d]\n' % (
                len(the_connection_map),
                len(the_addr_cache.cache),
            )
        )

def new_random_addr():
    for i in range (100):
        (ip, port) = the_addr_cache.random()
        if (ip, port) not in the_connection_map:
            if ip == '192.33.90.253':
                # filter out eth switzerland
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
        in_conn_sem.acquire (1)
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
    out_conn_sem.acquire (1)
    addr0 = get_my_addr (addr1)
    Connection (addr0, addr1)

# > x = read.table('/tmp/times.csv', header=T)
# > hist(x$time)
# > hist(x$time, breaks=seq(0,500))
# > hist(x$time, breaks=seq(0,500), xlim=c(0,60))
# > hist(x$time, breaks=seq(0,500), xlim=c(0,60), col="red")

def go (args):
    global the_addr_cache
    global the_block_db
    global the_hoover
    global in_conn_sem, out_conn_sem
    global h
    import coro
    the_addr_cache = AddressCache()
    the_block_db = bitcoin.BlockDB()
    the_hoover = BlockHoover()
    # install a real resolver
    coro.dns.cache.install()
    if args.monitor:
        import coro.backdoor
        coro.spawn (coro.backdoor.serve, unix_path='/tmp/caesure.bd')
    if args.webadmin:
        import coro.http
        import webadmin
        import zlib
        h = coro.http.server()
        if False:
            h.push_handler (webadmin.handler())
            coro.spawn (h.start, (('127.0.0.1', 9380)))
        else:
            h.push_handler (coro.http.handlers.auth_handler ({'foo': 'bar'}, webadmin.handler()))
            coro.spawn (h.start, (('', 8380)))
        h.push_handler (coro.http.handlers.coro_status_handler())
        h.push_handler (coro.http.handlers.favicon_handler (zlib.compress (webadmin.favicon)))
    in_conn_sem = coro.semaphore (args.incoming)
    out_conn_sem = coro.semaphore (args.outgoing)
    W ('args.serve=%r\n' % (args.serve,))
    if args.serve:
        for addr in args.serve:
            coro.spawn (serve, addr)
    if args.connect:
        for addr in args.connect:
            coro.spawn (connect, addr)
    coro.spawn (status_thread)
    coro.spawn (the_addr_cache.purge_thread)
    # give the servers time to start up and set addresses
    coro.sleep_relative (2)
    while 1:
        out_conn_sem.acquire (1)
        addr1 = new_random_addr()
        addr0 = get_my_addr (addr1)
        Connection (addr0, addr1)
        # avoid hammering the internets
        coro.sleep_relative (1)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument ('-o', '--outgoing', type=int, help="total number of outgoing connections", default=10)
    p.add_argument ('-i', '--incoming', type=int, help="total number of incoming connections", default=10)
    p.add_argument ('-s', '--serve', action="append", help="serve on this address", metavar='IP:PORT')
    p.add_argument ('-c', '--connect', action="append", help="connect to this address", metavar='IP:PORT')
    p.add_argument ('-m', '--monitor', action='store_true', help='run the monitor on /tmp/caesure.bd')
    p.add_argument ('-a', '--webui', action='store_true', help='run the web interface at http://localhost:8380/admin/')
    args = p.parse_args()
    coro.spawn (go, args)
    coro.event_loop()
