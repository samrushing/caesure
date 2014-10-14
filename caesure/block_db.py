# -*- Mode: Python -*-

import cPickle
import os
import sys
import coro
import caesure.proto

from caesure.bitcoin import *

BLOCKS_PATH = '/usr/local/caesure/blocks.bin'
METADATA_PATH = '/usr/local/caesure/metadata.bin'

W = coro.write_stderr

class TX (caesure.proto.TX):

    def copy (self):
        tx0 = TX()
        tx0.version = self.version
        tx0.lock_time = self.lock_time
        tx0.inputs = self.inputs[:]
        tx0.outputs = self.outputs[:]
        return tx0

    def get_hash (self):
        return dhash (self.render())

    def dump (self, fout=sys.stdout):
        D = fout.write
        D ('hash: %s\n' % (hexify (dhash (self.render())),))
        D ('inputs: %d\n' % (len(self.inputs)))
        for i in range (len (self.inputs)):
            (outpoint, index), script, sequence = self.inputs[i]
            try:
                redeem = pprint_script (parse_script (script))
            except ScriptError:
                redeem = script.encode ('hex')
            D ('%3d %064x:%d %r %d\n' % (i, outpoint, index, redeem, sequence))
        D ('%d outputs\n' % (len(self.outputs),))
        for i in range (len (self.outputs)):
            value, pk_script = self.outputs[i]
            pk_script = pprint_script (parse_script (pk_script))
            D ('%3d %s %r\n' % (i, bcrepr (value), pk_script))
        D ('lock_time: %s\n' % (self.lock_time,))

    def render (self):
        return self.pack()

    # Hugely Helpful: http://forum.bitcoin.org/index.php?topic=2957.20

    def get_ecdsa_hash (self, index, sub_script, hash_type):
        # XXX see script.cpp:SignatureHash() - looks like this is where
        #   we make mods depending on <hash_type>
        tx0 = self.copy()
        for i in range (len (tx0.inputs)):
            outpoint, script, sequence = tx0.inputs[i]
            if i == index:
                script = sub_script
            else:
                script = ''
            tx0.inputs[i] = outpoint, script, sequence
        return tx0.render() + struct.pack ('<I', hash_type)

    def verify0 (self, index, prev_outscript):
        outpoint, script, sequence = self.inputs[index]
        m = verifying_machine (prev_outscript, self, index)
        #print 'source script', pprint_script (parse_script (script))
        eval_script (m, parse_script (script))
        m.clear_alt()
        # should terminate with OP_CHECKSIG or its like
        #print 'redeem script', pprint_script (parse_script (prev_outscript))
        r = eval_script (m, parse_script (prev_outscript))
        if r is None:
            # if the script did not end in a CHECKSIG op, we need
            #   to check the top of the stack (essentially, OP_VERIFY)
            m.need (1)
            if not m.truth():
                raise VerifyError
        elif r == 1:
            pass
        else:
            # this can happen if r == 0 (verify failed) or r == -1 (openssl error)
            raise VerifyError

    def verify1 (self, pub_key, sig, to_hash):
        k = KEY()
        k.set_pubkey (pub_key)
        return k.verify (to_hash, sig)

class BadBlock (Exception):
    pass

class BLOCK (caesure.proto.BLOCK):

    def dump (self, fout=sys.stdout):
        fout.write (
            'version:%d\n'
            'prev_block:%s\n'
            'merkle_root:%r\n'
            'timestamp:%s\n'
            'bits:%08x\n'
            'nonce:%d\n' % (
                self.version,
                self.prev_block,
                self.merkle_root,
                self.timestamp,
                self.bits,
                self.nonce
            )
        )
        for i in range (len (self.transactions)):
            fout.write ('tx %d {\n' % (i,))
            self.transactions[i].dump (fout)
            fout.write ('}\n')

    def __len__ (self):
        return len (self.transactions)

    def get_height (self):
        if self.version < 2:
            raise ValueError ("no block height in version 1 blocks")
        else:
            tx0 = self.transactions[0]
            coinbase = tx0.inputs[0]
            ((outpoint_hash, outpoint_index), script, sequence) = coinbase
            # Note: we can't use parse_script here because coinbases are *not*
            #  guaranteed to be proper scripts.  At least yet.
            nbytes = ord(script[0])
            height = unrender_int (script[1:1 + nbytes])
            return height

    def make_TX (self):
        return TX()

    def check_bits (self):
        shift  = self.bits >> 24
        target = (self.bits & 0xffffff) * (1 << (8 * (shift - 3)))
        val = int (self.name)
        return val < target

    def get_merkle_hash (self):
        hl = [dhash (t.raw) for t in self.transactions]
        while 1:
            if len(hl) == 1:
                return Name (hl[0])
            if len(hl) % 2 != 0:
                hl.append (hl[-1])
            hl0 = []
            for i in range (0, len (hl), 2):
                hl0.append (dhash (hl[i] + hl[i + 1]))
            hl = hl0

    # see https://en.bitcoin.it/wiki/Protocol_rules
    def check_rules (self):
        if not len(self.transactions):
            raise BadBlock ("zero transactions")
        elif not self.check_bits():
            raise BadBlock ("did not achieve target")
        elif (time.time() - self.timestamp) < (-60 * 60 * 2):
            raise BadBlock ("block from the future")
        else:
            for i in range (len (self.transactions)):
                tx = self.transactions[i]
                if i == 0 and (len (tx.inputs) != 1 or tx.inputs[0][0] != NULL_OUTPOINT):
                    raise BadBlock ("first transaction not a generation")
                elif i == 0 and not (2 <= len (tx.inputs[0][1]) <= 100):
                    raise BadBlock ("bad sig_script in generation transaction")
                elif i > 0:
                    for outpoint, sig_script, sequence in tx.inputs:
                        if outpoint == NULL_OUTPOINT:
                            raise BadBlock ("transaction other than the first is a generation")
                for value, _ in tx.outputs:
                    if value > MAX_MONEY:
                        raise BadBlock ("too much money")
                    # XXX not checking SIGOP counts since we don't really implement the script engine.
            # check merkle hash
            if self.merkle_root != self.get_merkle_hash():
                raise BadBlock ("merkle hash doesn't match")
        # XXX more to come...

# --------------------------------------------------------------------------------
# BlockDB file format: (<8 bytes of size> <block>)+
#
# Note: this is very close to the bitcoin.dat torrent format, in fact they can be
#   converted in-place between each other.

# XXX consider mmap

class BlockDB:

    def __init__ (self, read_only=False):
        self.read_only = read_only
        self.blocks = {}
        self.prev = {}
        self.block_num = {ZERO_NAME: -1}
        self.num_block = {}
        self.last_block = 0
        self.new_block_cv = coro.condition_variable()
        self.file = None
        if os.path.isfile (METADATA_PATH):
            f = open (METADATA_PATH, 'rb')
            start_scan = self.load_metadata (f)
            f.close()
        else:
            start_scan = 0
        self.scan_block_chain (start_scan)
        coro.spawn (self.metadata_thread)

    def get_header (self, name):
        path = os.path.join ('blocks', name)
        return open (path).read (80)

    metadata_flush_time = 5 * 60 * 60              # five hours

    def metadata_thread (self):
        while 1:
            coro.sleep_relative (self.metadata_flush_time)
            self.dump_metadata()

    def dump_metadata (self):
        W ('saving metadata...')
        t0 = timer()
        fileob = open (METADATA_PATH + '.tmp', 'wb')
        cPickle.dump (1, fileob, 2)
        cPickle.dump (len(self.blocks), fileob, 2)
        for a, pos in self.blocks.iteritems():
            cPickle.dump (
                [str(a), pos, self.block_num[a], str(self.prev[a])],
                fileob,
                2
            )
        fileob.close()
        os.rename (METADATA_PATH + '.tmp', METADATA_PATH)
        W ('done %.2f secs\n' % (t0.end(),))

    def load_metadata (self, fileob):
        W ('reading metadata...')
        t0 = timer()
        version = cPickle.load (fileob)
        assert (version == 1)
        nblocks = cPickle.load (fileob)
        max_block = 0
        max_pos = 0
        for i in xrange (nblocks):
            name, pos, num, prev = cPickle.load (fileob)
            name = Name (name)
            prev = Name (prev)
            self.blocks[name] = pos
            max_pos = max (pos, max_pos)
            self.prev[name] = prev
            self.num_block.setdefault (num, set()).add (name)
            self.block_num[name] = num
            max_block = max (max_block, num)
        self.last_block = max_block
        W ('done %.2f secs (last_block=%d)\n' % (t0.end(), self.last_block))
        return max_pos

    def scan_block_chain (self, last_pos):
        from caesure.proto import unpack_block_header
        if not os.path.isfile (BLOCKS_PATH):
            open (BLOCKS_PATH, 'wb').write('')
        f = open (BLOCKS_PATH, 'rb')
        W ('reading block headers...')
        f.seek (0, 2)
        eof_pos = f.tell()
        f.seek (last_pos)
        W ('starting at pos %r...' % (last_pos,))
        t0 = timer()
        count = 0
        while 1:
            pos = f.tell()
            size = f.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
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
                    W ('(%d)' % (bn,))
                count += 1
        W ('done. scanned %d blocks in %.02f secs\n' % (count, t0.end()))
        f.close()
        self.read_only_file = open (BLOCKS_PATH, 'rb')
        if count > 1000:
            self.dump_metadata()

    def open_for_append (self):
        # reopen in append mode
        self.file = open (BLOCKS_PATH, 'ab')

    def get_block (self, name):
        pos = self.blocks[name]
        self.read_only_file.seek (pos)
        size = self.read_only_file.read (8)
        size, = struct.unpack ('<Q', size)
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
            W ('ignoring block we already have: %r\n' % (name,))
        elif not self.block_num.has_key (block.prev_block) and block.prev_block != ZERO_NAME:
            # if we don't have the previous block, there's no
            #  point in remembering it at all.  toss it.
            # XXX not true.  when we are on an orphaned fork we will see orphans here,
            #   and we need to process them correctly (i.e., set them aside while we
            #   request the prev nodes).
            pass
        else:
            self.write_block (name, block)
            W ('[waking new_block cv]')
            self.new_block_cv.wake_all (block)

    def write_block (self, name, block):
        if self.file is None:
            self.open_for_append()
        size = len (block.raw)
        pos = self.file.tell()
        self.file.write (struct.pack ('<Q', size))
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
