# -*- Mode: Python -*-

import os
import pickle
import random

import coro

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

