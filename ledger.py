# -*- Mode: Python -*-

# This is currently a stand-alone tool for building a ledger database
#   in memory.  It mounts the blockchain file in read-only mode and
#   does a pruning scan.

import struct
from caesure._script import parse_script
from caesure.script import pprint_script, OPCODES
from bitcoin import BlockDB, key_to_address, rhash, bcrepr
import caesure.proto
import cPickle
import bitcoin

from pprint import pprint as pp

import sys

W = sys.stderr.write

pack_u64 = caesure.proto.pack_u64

def compute_rewards (n):
    l = []
    r = 50 * 100000000
    for i in range (n):
        l.append (r)
        r /= 2
    return l

# 60 years' worth
reward_schedule = compute_rewards (15)

def compute_reward (height):
    return reward_schedule [height // 210000]

def is_push (x):
    return x[0] == 0

def is_cond (x):
    return x[0] == 1

def is_op (x, code):
    return x[0] == 2 and x[1] == code

def is_check (x):
    return x[0] == 3

def is_checksig (x):
    return x[0] == 3 and x[1] == OPCODES.OP_CHECKSIG

def is_checkmultisig (x):
    return x[0] == 3 and x[1] == OPCODES.OP_CHECKMULTISIG

def is_normal_tx (s):
    if (len(s) == 5
            and s[0] == (2, OPCODES.OP_DUP)
            and s[1] == (2, OPCODES.OP_HASH160)
            and s[-2] == (2, OPCODES.OP_EQUALVERIFY)
            and is_check (s[-1])):
        return 'normal', key_to_address (s[2][1])
    else:
        return None

def is_pubkey_tx (s):
    if len(s) == 2 and is_check (s[1]):
        return 'pubkey', key_to_address (rhash (s[0][1]))
    else:
        return None

def is_p2sh_tx (s):
    if (len(s) == 3
            and s[0] == (2, OPCODES.OP_HASH160)
            and s[2] == (2, OPCODES.OP_EQUAL)
            and s[1][0] == 0
            and len(s[1][1]) == 20):
        return 'p2sh', key_to_address (s[1][1], 5)

OP_NUMS = {}
for i in range (0x51, 0x61):
    OP_NUMS[i] = i - 0x50

def is_multi_tx (s):
    # OP_3 pubkey0 pubkey1 pubkey2 OP_3 OP_CHECKMULTISIG
    if is_checkmultisig (s[-1]):
        n0 = OP_NUMS.get (s[0][1], None)
        n1 = OP_NUMS.get (s[-2][1], None)
        if n0 is None or n1 is None:
            return None
        elif n1 == (len(s) - 3):
            for i in range (1, 1 + n1):
                if not s[i][0] == 0:
                    return None
            val = '%d/%d:%s' % (
                n0,
                n1,
                '/'.join ([key_to_address (rhash (s[i][1])) for i in range (1, 1 + n1)])
            )
            return 'multi', val
        else:
            return None

class Transaction_Map:
    def __init__ (self):
        self.load_state()
        self.bad_scripts = []
        self.other_scripts = []
        self.too_big = 0

    def load_state (self):
        try:
            self.outpoints = cPickle.load (open ('/usr/local/bitcoin/outpoints.bin', 'rb'))
            self.monies = cPickle.load (open ('/usr/local/bitcoin/monies.bin', 'rb'))
            info        = cPickle.load (open ('/usr/local/bitcoin/info.bin', 'rb'))
            self.height, self.total, self.lost, self.fees, self.tx_kinds  = info
        except IOError:
            self.outpoints = {}
            self.monies = {}
            self.height = -1
            self.total = 0
            self.lost = 0
            self.fees = 0
            self.tx_kinds = {'normal': 0, 'pubkey': 0, 'p2sh': 0, 'multi': 0, 'other': 0}

    def save_state (self):
        cPickle.dump (self.outpoints, open ('/usr/local/bitcoin/outpoints.bin', 'wb'), 2)
        cPickle.dump (self.monies, open ('/usr/local/bitcoin/monies.bin', 'wb'), 2)
        info = (self.height, self.total, self.lost, self.fees, self.tx_kinds)
        cPickle.dump (info, open ('/usr/local/bitcoin/info.bin', 'wb'), 2)

    def add_to_addr (self, addr, amt):
        self.total += amt
        if addr:
            v = self.monies.get (addr, 0)
            self.monies[addr] = v + amt
        else:
            W ('add_to_addr %r %r failed\n' % (addr, amt))

    def sub_from_addr (self, addr, amt):
        self.total -= amt
        if addr:
            v = self.monies.get (addr, 0)
            if v:
                v0 = v - amt
                if v0 == 0:
                    del self.monies[addr]
                else:
                    self.monies[addr] = v0
            elif amt > 0:
                W ('sub_from_addr %r %d underflow\n' % (addr, amt))
            else:
                pass
        else:
            W ('sub_from_addr %r %r failed\n' % (addr, amt))

    def get_output_addr (self, tx_name, pk_script):
        if len(pk_script) > 500:
            # don't bother to parse/remember silly scripts
            self.too_big += 1
            return None
        try:
            script = parse_script (pk_script)
            probe = is_normal_tx (script)
            if not probe:
                probe = is_pubkey_tx (script)
                if not probe:
                    probe = is_p2sh_tx (script)
                    if not probe:
                        probe = is_multi_tx (script)
            if probe:
                kind, addr = probe
                self.tx_kinds[kind] += 1
                return addr
            else:
                self.other_scripts.append ((tx_name, script))
                return None
        except:
            W ('[bad script]\n')
            self.bad_scripts.append ((tx_name, pk_script))
            return None

    def store_outputs (self, tx):
        output_sum = 0
        for i in range (len (tx.outputs)):
            # inputs are referenced by (txhash,index) so we need to store this into db,
            #   and only remove it when it has been spent.  so probably we need (txhash,index)->(amt,script)
            #   alternatively we could store it as an offset,size into the db file... but probably not worth it.
            amt, pk_script = tx.outputs[i]
            addr = self.get_output_addr (tx.name, pk_script)
            if addr is None and amt > 0:
                W ('nodecode amt=%s tx=%r i=%d\n' % (amt, tx.name, i))
            if len(pk_script) > 500:
                W ('%r len(script) = %d\n' % (tx.name, len(pk_script)))
            value = cPickle.dumps ((amt, pk_script, addr), 2)
            # XXX consider giving access to the raw name in proto.pyx
            key = (tx.name, i)
            self.outpoints[key] = value
            if amt > 0:
                self.add_to_addr (addr, amt)
                output_sum += amt
        return output_sum

    def feed_block (self, b, height):
        # assume coinbase is ok for now
        tx0 = b.transactions[0]
        reward0 = self.store_outputs (tx0)
        fees = 0
        for tx in b.transactions[1:]:
            # verify each transaction
            # first, we need the output script for each of the inputs
            input_sum = 0
            for i in range (len (tx.inputs)):
                (outpoint, index), script, sequence = tx.inputs[i]
                key = (outpoint, index)
                amt, oscript, addr = cPickle.loads (self.outpoints[key])
                del self.outpoints[key]
                self.sub_from_addr (addr, amt)
                input_sum += amt
            output_sum = self.store_outputs (tx)
            fees += input_sum - output_sum
        self.fees += fees
        reward1 = compute_reward (height)
        if reward1 + fees != reward0:
            lost = (reward1 + fees) - reward0
            W ('reward mismatch height=%d lost=%s\n' % (height, lost))
            self.lost += lost
        self.height = height

def get_names():
    b = db.by_num (db.last_block)
    r = []
    name = b.name
    while 1:
        r.append (name)
        name = db.prev[name]
        if name == bitcoin.ZERO_NAME:
            break
    r.reverse()
    return r

def go():
    names = get_names()
    i = 0
    for name in names:
        if i % 10000 == 0:
            W ('%d ' % (i,))
        if i == txmap.height + 1:
            txmap.feed_block (db[name], i)
        elif i <= txmap.height:
            pass
        else:
            W ('oops, block too high?\n')
            import pdb; pdb.set_trace()
        i += 1
        coro.yield_slice()
    W ('\n')
    W ('       total=%s\n' % (bcrepr (txmap.total)))
    W ('        lost=%s\n' % (bcrepr (txmap.lost)))
    W ('        fees=%s\n' % (bcrepr (txmap.fees)))
    W ('txns:\n')
    kinds = txmap.tx_kinds
    W ('  normal: %d\n' % (kinds['normal'],))
    W ('  pubkey: %d\n' % (kinds['pubkey'],))
    W ('    p2sh: %d\n' % (kinds['p2sh'],))
    W ('   multi: %d\n' % (kinds['multi'],))
    W ('   other: %d\n' % (kinds['other'],))

import bitcoin
db = BlockDB (read_only=True)
bitcoin.the_block_db = db
txmap = Transaction_Map()

if '-c' not in sys.argv:

    import coro
    import coro.backdoor

    coro.spawn (go)
    coro.spawn (coro.backdoor.serve, 8025)
    coro.event_loop()
