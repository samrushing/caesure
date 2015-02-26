# -*- Mode: Python -*-

import os
import sys
import coro
import caesure.proto

from caesure.bitcoin import *

import coro.asn1.python
import coro.asn1.ber

from coro.log import Facility

LOG = Facility ('db')

# pub/sub for new blocks.

class BlockBroker:

    def __init__ (self):
        self.q = coro.fifo()
        self.subs = set()
        coro.spawn (self.fanout_thread)

    def fanout_thread (self):
        # Note: this thread is overkill, just have publish do the fanout.
        while 1:
            ob = self.q.pop()
            for sub in self.subs:
                sub.push (ob)
    
    def subscribe (self):
        ob = coro.fifo()
        self.subs.add (ob)
        return ob
        
    def unsubscribe (self, ob):
        self.subs.remove (ob)

    def publish (self, ob):
        self.q.push (ob)

# BlockDB file format: (<8 bytes of size> <block>)+
#
# Note: this is very close to the bitcoin.dat torrent format, in fact they can be
#   converted in-place between each other.

class BlockDB:

    blocks_path = 'blocks.bin'
    metadata_path = 'metadata.bin'

    def __init__ (self, read_only=True):
        from __main__ import G
        self.read_only = read_only
        self.blocks = {}
        self.prev = {}
        self.block_num = {ZERO_NAME: -1}
        self.num_block = {}
        self.last_block = 0
        self.block_broker = BlockBroker()
        self.file = None
        metadata_path = os.path.join (G.args.base, self.metadata_path)
        if os.path.isfile (metadata_path):
            f = open (metadata_path, 'rb')
            start_scan = self.load_metadata (f)
            f.close()
        else:
            start_scan = 0
        self.scan_block_chain (start_scan)
        coro.spawn (self.metadata_thread)

    metadata_flush_time = 5 * 60 * 60              # five hours

    def metadata_thread (self):
        while 1:
            coro.sleep_relative (self.metadata_flush_time)
            self.dump_metadata()

    def dump_metadata (self):
        from coro.asn1.data_file import DataFileWriter
        from __main__ import G
        LOG ('saving metadata', 'start')
        t0 = timer()
        metadata_path = os.path.join (G.args.base, self.metadata_path)
        fileob = open (metadata_path + '.tmp', 'wb')
        df = DataFileWriter (fileob)
        version = 1
        df.write_object ([version, len(self.blocks)])
        for a, pos in self.blocks.iteritems():
            df.write_object (
                [str(a), pos, self.block_num[a], str(self.prev[a])]
            )
        fileob.close()
        os.rename (metadata_path + '.tmp', metadata_path)
        LOG ('saving metadata', 'stop', t0.end())

    def load_metadata (self, fileob):
        from coro.asn1.data_file import DataFileReader
        LOG ('loading metadata', 'start')
        t0 = timer()
        max_block = 0
        max_pos = 0
        df = DataFileReader (fileob)
        try:
            info = df.read_object()
            version = info[0]
            assert (version == 1)
            version, nblocks = info
            for i in xrange (nblocks):
                name, pos, num, prev = df.read_object()
                name = Name (name)
                prev = Name (prev)
                self.blocks[name] = pos
                max_pos = max (pos, max_pos)
                self.prev[name] = prev
                self.num_block.setdefault (num, set()).add (name)
                self.block_num[name] = num
                max_block = max (max_block, num)
            self.last_block = max_block
        except coro.asn1.ber.DecodeError:
            LOG ('error decoding metadata')
        LOG ('loading metadata', 'stop', t0.end(), self.last_block)
        return max_pos

    def _read_size (self, size):
        if len(size) == 0:
            return 0
        else:
            size_a, size_b = struct.unpack ('<LL', size)
            if size_a == 0xd9b4bef9:
                # bootstrap.dat magic
                return size_b
            else:
                # caesure 64-bit size.
                return size_a

    def scan_block_chain (self, last_pos):
        from caesure.proto import unpack_block_header
        from __main__ import G
        blocks_path = os.path.join (G.args.base, self.blocks_path)
        if not os.path.isfile (blocks_path):
            open (blocks_path, 'wb').write('')
        f = open (blocks_path, 'rb')
        LOG ('scan', 'reading block headers')
        f.seek (0, 2)
        eof_pos = f.tell()
        f.seek (last_pos)
        LOG ('scan', 'start', last_pos)
        t0 = timer()
        count = 0
        while 1:
            pos = f.tell()
            size = self._read_size (f.read (8))
            if not size:
                break
            else:
                header = f.read (80)
                b = caesure.proto.BLOCK()
                b.unpack (header, True)
                # skip the rest of the block
                f.seek (size - 80, 1)
                if f.tell() > eof_pos:
                    break
                name = Name (dhash (header))
                bn = 1 + self.block_num[b.prev_block]
                self.prev[name] = b.prev_block
                self.block_num[name] = bn
                self.num_block.setdefault (bn, set()).add (name)
                self.blocks[name] = pos
                self.last_block = max (self.last_block, bn)
                if count % 1000 == 0:
                    LOG ('scan', bn)
                count += 1
        LOG ('scan', 'done', count, t0.end())
        f.close()
        blocks_path = os.path.join (G.args.base, self.blocks_path)
        self.read_only_file = open (blocks_path, 'rb')
        if count > 1000:
            self.dump_metadata()

    def open_for_append (self):
        from __main__ import G
        blocks_path = os.path.join (G.args.base, self.blocks_path)
        # reopen in append mode
        self.file = open (blocks_path, 'ab')

    def get_header (self, name, size=80):
        pos = self.blocks[name]
        self.read_only_file.seek (pos)
        bsize = self._read_size (self.read_only_file.read (8))
        header = self.read_only_file.read (size)
        if len(header) == size:
            return header
        else:
            raise EOFError

    def get_block (self, name):
        pos = self.blocks[name]
        self.read_only_file.seek (pos)
        size = self._read_size (self.read_only_file.read (8))
        block = self.read_only_file.read (size)
        if len(block) == size:
            return block
        else:
            raise EOFError

    def __getitem__ (self, name):
        if len(name) == 64:
            name = caesure.proto.name_from_hex (name)
        b = BLOCK()
        b.unpack (self.get_block (name))
        return b

    def get_names (self):
        h, name = self.get_highest_uncontested_block()
        names = []
        while 1:
            probe = self.prev.get (name, None)
            if probe is not None:
                names.append (name)
                name = probe
            else:
                break
        names.reverse()
        return names

    def __iter__ (self):
        for name in self.get_names():
            yield self[name]

    def __len__ (self):
        return len (self.blocks)

    def by_num (self, num):
        # fetch *one* of the set, beware all callers of this
        return self[list(self.num_block[num])[0]]

    def next (self, name):
        # synthesize a name->successor[s] map
        num = self.block_num[name]
        probe = self.num_block.get (num + 1, None)
        if probe is not None:
            r = []
            for name0 in probe:
                if self[name0].prev_block == name:
                    r.append (name0)
            return r
        else:
            return []

    def add (self, name, block):
        if self.blocks.has_key (name):
            LOG ('ignoring', 'have', repr(name))
        elif not self.block_num.has_key (block.prev_block) and block.prev_block != ZERO_NAME:
            # if we don't have the previous block, there's no
            #  point in remembering it at all.  toss it.
            # XXX not true.  when we are on an orphaned fork we will see orphans here,
            #   and we need to process them correctly (i.e., set them aside while we
            #   request the prev nodes).
            LOG ('ignoring', 'nochain', repr(name))
        else:
            self.write_block (name, block)
            LOG ('add', repr(name), self.block_num[name])
            self.block_broker.publish (block)

    def write_block (self, name, block):
        if self.file is None:
            self.open_for_append()
        size = len (block.raw)
        pos = self.file.tell()
        self.file.write (struct.pack ('<LL', 0xd9b4bef9, size))
        self.file.write (block.raw)
        self.file.flush()
        self.prev[name] = block.prev_block
        self.blocks[name] = pos
        if block.prev_block == ZERO_NAME:
            i = -1
        else:
            i = self.block_num[block.prev_block]
        self.block_num[name] = i + 1
        self.num_block.setdefault (i + 1, set()).add (name)
        self.last_block = i + 1

    def has_key (self, name):
        return self.prev.has_key (name)

    def __contains__ (self, name):
        return name in self.prev

    def get_highest_uncontested_block (self):
        h = self.last_block
        while 1:
            if len(self.num_block[h]) == 1:
                break
            else:
                h -= 1
        return h, list(self.num_block[h])[0]

    # see https://en.bitcoin.it/wiki/Satoshi_Client_Block_Exchange
    # "The getblocks message contains multiple block hashes that the
    #  requesting node already possesses, in order to help the remote
    #  note find the latest common block between the nodes. The list of
    #  hashes starts with the latest block and goes back ten and then
    #  doubles in an exponential progression until the genesis block is
    #  reached."

    def set_for_getblocks (self):
        n = self.last_block
        result = []
        i = 0
        step = 1
        while n > 0:
            name = list(self.num_block[n])[0]
            result.append (name)
            n -= step
            i += 1
            if i >= 10:
                step *= 2
        return result


if __name__ == '__main__':
    import argparse
    class GlobalState:
        pass
    G = GlobalState()
    p = argparse.ArgumentParser()
    p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
    G.args = p.parse_args()
    db = G.block_db = BlockDB (read_only=True)
