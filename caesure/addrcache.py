# -*- Mode: Python -*-

import os
import pickle
import random

import coro

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

class AddressCache:

    def __init__ (self):
        global G
        from __main__ import G
        self.cache = {}
        self.load()

    def add (self, timestamp, entry):
        # each entry consists of (services, (addr, port))
        (services, (ip, port)) = entry
        if is_routable (ip):
            self.cache[(ip, port)] = (timestamp, services)

    save_path = 'peers.bin'

    def save (self):
        save_path = os.path.join (G.args.base, self.save_path)
        # XXX use DataFile here.
        pickle.dump (self.cache, open (save_path, 'wb'), 2)

    def load (self):
        save_path = os.path.join (G.args.base, self.save_path)
        try:
            self.cache = pickle.load (open (save_path, 'rb'))
            G.log ('address-cache', 'load', len(self.cache))
        except IOError:
            pass
        if not self.cache:
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

