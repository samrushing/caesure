# -*- Mode: Cython; indent-tabs-mode:nil -*-
# distutils: language = c++

# see:
#  http://eternallyconfuzzled.com/tuts/datastructures/jsw_tut_andersson.aspx
#  http://en.wikipedia.org/wiki/AA_tree

# this is a customized version of aatree/faa.pyx

# the map of utxo is stored in memory as a 'persistent' data structure,
#   meaning that we can store multiple root pointers to multiple versions
#   of the map that share most of their structure.
#
# See: https://en.wikipedia.org/wiki/Persistent_data_structure
# and Okasaki's "Purely Functional Data Structures".

from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t
from libc.string cimport memcmp, memcpy

from libcpp.pair cimport pair
from libcpp.vector cimport vector
from libcpp.string cimport string
from cython.operator cimport dereference as deref, preincrement as inc

# XXX consider the security implications of using only half the txname.
# can someone that knows we are using only half do something evil?

cdef enum:
    # 16 bytes of key, 2 bytes of index.
    KEYSIZE = 18

cdef class aa_node:
    cdef readonly uint8_t level
    cdef readonly aa_node l, r
    cdef char[KEYSIZE] k
    cdef readonly uint64_t amt
    cdef readonly bytes script

    def __cinit__ (self, int level, aa_node l, aa_node r):
        self.level = level
        self.l = l
        self.r = r

    property key:
        def __get__ (self):
            return self.k[:KEYSIZE]
        def __set__ (self, char * val):
            memcpy (self.k, val, KEYSIZE)

    cdef aa_node copy (self):
        cdef aa_node n
        if self is tree_nil:
            return self
        else:
            return copy_node (self.level, self.l, self.r, self)

cdef aa_node copy_node (int level, aa_node l, aa_node r, aa_node other):
    cdef aa_node n = aa_node (level, l, r)
    memcpy (<char*>n.k, <char*>other.k, KEYSIZE)
    n.amt = other.amt
    n.script = other.script
    return n

cdef make_node (int level, aa_node l, aa_node r, char * key, uint64_t amt, bytes script):
    cdef aa_node node = aa_node (level, l, r)
    memcpy (<char*>node.k, <char*>key, KEYSIZE)
    node.amt = amt
    node.script = script
    return node

import sys
W = sys.stderr.write

cdef char ZERO[32]
# this global node acts as a sentinel
cdef aa_node tree_nil
tree_nil = aa_node (0, tree_nil, tree_nil)
tree_nil.l = tree_nil
tree_nil.r = tree_nil

# non-recursive skew and split

cdef aa_node skew (aa_node n):
    if n.level != 0 and n.l.level == n.level:
        return copy_node (
            n.level,
            n.l.l,
            copy_node (n.level, n.l.r, n.r, n),
            n.l
        )
    else:
        return n

cdef aa_node split (aa_node n):
    if n.level != 0 and n.r.r.level == n.level:
        return copy_node (
            n.r.level + 1,
            copy_node (n.level, n.l, n.r.l, n),
            n.r.r,
            n.r
        )
    else:
        return n

cdef aa_node tree_insert (aa_node n, char * key, uint64_t amt, bytes script):
    cdef aa_node n0
    cdef int compare
    if n.level == 0:
        return make_node (1, tree_nil, tree_nil, key, amt, script)
    else:
        compare = memcmp (n.k, key, 18)
        if compare > 0:
            n0 = copy_node (n.level, tree_insert (n.l, key, amt, script), n.r, n)
        else:
            n0 = copy_node (n.level, n.l, tree_insert (n.r, key, amt, script), n)
        return split (skew (n0))

# build a completish tree from sorted input
cdef aa_node tree_build (data_gen, int lo, int hi):
    cdef int mid = ((hi - lo) / 2) + lo
    cdef aa_node l, r
    cdef uint64_t amt
    cdef bytes script
    if mid == hi == lo:
        return tree_nil
    else:
        l = tree_build (data_gen, lo, mid)
        key, amt, script = data_gen.next()
        r = tree_build (data_gen, mid + 1, hi)
        return make_node (l.level + 1, l, r, key, amt, script)

# the Stark Fist of Removal.  This class is just a placeholder for the two static/global variables
#  used in the deletion algorithm.  [plus the amt & script values we are popping]
cdef class fist:
    cdef aa_node heir
    cdef aa_node item
    cdef bint removed
    cdef amt
    cdef script
    def __cinit__ (self):
        self.heir = tree_nil
        self.item = tree_nil
        self.removed = False

# This is based on julienne's version of anderson's deletion algorithm.
#  I found it a little easier to reason about (w.r.t. immutability).

cdef aa_node tree_remove (fist self, aa_node root, char * key):
    cdef aa_node root0
    cdef int compare
    # search down the tree
    if root is not tree_nil:
        self.heir = root
        compare = memcmp (root.k, key, KEYSIZE)
        root0 = root.copy()
        if compare >= 0:
            self.item = root0
            root0.l = tree_remove (self, root0.l, key)
        else:
            root0.r = tree_remove (self, root0.r, key)
    else:
        root0 = root
    if root is self.heir:
        # at the bottom, remove
        if self.item is not tree_nil and memcmp (self.item.k, key, KEYSIZE) == 0:
            # empty, remove it
            self.removed = True
            self.amt = self.item.amt
            self.script = self.item.script
            memcpy (self.item.k, self.heir.k, KEYSIZE)
            self.item.amt = self.heir.amt
            self.item.script = self.heir.script
            self.item = tree_nil
            # here, we diverge from AA's paper, where he always return root0.r.
            if root0.r is tree_nil:
                return root0.l
            else:
                return root0.r
        else:
            return root0
    else:
        # not at the bottom, rebalance
        if root0.l.level < root0.level - 1 or root0.r.level < root0.level - 1:
            root0.level -= 1
            if root0.r.level > root0.level:
                root0.r = root0.r.copy()
                root0.r.level = root0.level
            root0 = skew (root0)
            root0.r = skew (root0.r)
            root0.r.r = skew (root0.r.r.copy())
            root0 = split (root0)
            root0.r = split (root0.r)
            return root0
        else:
            return root0

cdef int tree_size (aa_node n):
    if n is tree_nil:
        return 0
    else:
        return 1 + tree_size (n.l) + tree_size (n.r)

def walk (aa_node n):
    if n is not tree_nil:
        for x in walk (n.l):
            yield x
        yield n
        for x in walk (n.r):
            yield x

def walk_depth (aa_node n, int depth=0):
    cdef aa_node x
    cdef int d
    if n is not tree_nil:
        for x, d in walk_depth (n.l, depth + 1):
            yield x, d
        yield n, depth
        for x, d in walk_depth (n.r, depth + 1):
            yield x, d

def verify (aa_node t):
    cdef aa_node n
    cdef int h
    h = t.level
    for n in walk (t):
        assert n.l.level != n.level
        assert not (n.level == n.r.level and n.level == n.r.r.level)

def dump (t):
    W ('---\n')
    for n, d in walk_depth (t, 0):
        W ('%s%4d %r\n' % ('  ' * d, n.level, n.k[:KEYSIZE]))

cdef bytes uint16_be (uint16_t n):
    cdef uint8_t result[2]
    result[0] = (n >> 8) & 0xff
    result[1] = (n >> 0) & 0xff
    return result[:2]

cpdef bytes make_key (bytes txname, uint16_t index):
    return txname[:16] + uint16_be (index)

cdef class UTXO_Map:

    cdef public aa_node root
    cdef public uint32_t length

    def __init__ (self):
        self.root = tree_nil
        self.length = 0

    def compute_length (self):
        return tree_size (self.root)

    def __len__ (self):
        return self.length

    def build (self, gen, size):
        self.root = tree_build (gen, 0, size)
        self.length = size

    def copy (self):
        m = UTXO_Map()
        m.root = self.root
        m.length = self.length
        return m

    cdef aa_node _search (self, bytes key):
        cdef aa_node search = self.root
        cdef int compare
        while 1:
            if search == tree_nil:
                return tree_nil
            else:
                compare = memcmp (search.k, <char*>key, KEYSIZE)
                if compare == 0:
                    return search
                elif compare < 0:
                    search = search.r
                else:
                    search = search.l

    def __contains__ (self, object key):
        cdef aa_node probe = self._search (key)
        return probe is not tree_nil

    def get_utxo (self, bytes name, int index):
        cdef bytes key = make_key (name, index)
        cdef aa_node probe = self._search (key)
        if probe is not tree_nil:
            return probe.amt, probe.script
        else:
            raise KeyError ((name, index))

    def __iter__ (self):
        for node in walk (self.root):
            yield node.key, node.amt, node.script

    def verify (self):
        verify (self.root)

    def dump (self, fout):
        for n, d in walk_depth (self.root, 0):
            fout.write ('%s%4d %r:%r\n' % ('  ' * d, n.level, n.key.encode('hex'), n.amt, n.script))

    def new_entry (self, bytes txname, object vals):
        for index, amt, script in vals:
            self.root = tree_insert (self.root, make_key (txname, index), amt, script)
        self.length += len(vals)

    def pop_utxo (self, bytes txname, int index):
        cdef bytes key = make_key (txname, index)
        f = fist()
        self.root = tree_remove (f, self.root, key)
        if f.removed:
            self.length -= 1
            return f.amt, f.script
        else:
            raise KeyError ((txname, index))

# -------------------------------------------------------------------
# This is a straightforward STL version of the map, used just for
# the initial scan.  It's much faster because it's non-persistent.
# -------------------------------------------------------------------

from libcpp.pair cimport pair
from libcpp.map cimport map
from libcpp.set cimport set

# Note: if you get an error here, you need to upgrade cython.
ctypedef pair [uint64_t, string] outpoint_val
ctypedef map [uint16_t, outpoint_val] outpoint_map
ctypedef map [string, outpoint_map] utxo_map

cdef class UTXO_Scan_Map:

    cdef utxo_map m

    def __len__ (self):
        # Note: manually tracking the length here screws up because of two duplicate coinbase txns:
        # d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599 91812 91842
        # e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468 91722 91880 
        cdef map[string, outpoint_map].iterator i0
        cdef long n = 0
        i0 = self.m.begin()
        while i0 != self.m.end():
            n += deref(i0).second.size()
            inc(i0)
        return n

    def new_entry (self, bytes txname, object vals):
        cdef map[string, outpoint_map].iterator i0
        cdef bytes script
        cdef uint64_t amt
        i0 = self.m.insert (
            pair[string, outpoint_map](
                txname, outpoint_map()
            )
        ).first
        for index, amt, script in vals:
            deref(i0).second[index] = (amt, script)

    def __contains__ (self, bytes txname):
        cdef map[string, outpoint_map].iterator i0
        i0 = self.m.find (txname)
        return i0 != self.m.end()

    def pop_utxo (self, bytes txname, int index):
        cdef map[string, outpoint_map].iterator i0
        cdef map[uint16_t, outpoint_val].iterator i1
        cdef bytes script
        cdef uint64_t amt
        i0 = self.m.find (txname)
        if i0 == self.m.end():
            raise KeyError (txname)
        else:
            i1 = deref(i0).second.find (index)
            if i1 == deref(i0).second.end():
                raise KeyError ((txname, index))
            else:
                amt, script = deref(i1).second
                deref(i0).second.erase (i1)
                if deref(i0).second.size() == 0:
                    self.m.erase (i0)
                return amt, script

    def __iter__ (self):
        cdef map[string, outpoint_map].iterator i0
        cdef map[uint16_t, outpoint_val].iterator i1
        i0 = self.m.begin()
        while i0 != self.m.end():
            i1 = deref(i0).second.begin()
            while i1 != deref (i0).second.end():
                index, (amt, script) = deref (i1)
                yield make_key (deref(i0).first, index), amt, script
                inc (i1)
            inc(i0)
