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

cdef struct outpoint:
    uint16_t index
    uint64_t amt
    string script


# you may be tempted to do this, but don't.  it *really* slows things down.
#@cython.freelist(200)

cdef class outpoint_set:
    cdef vector[outpoint] v

    def __init__ (self, vals):
        self.val = vals

    def __len__ (self):
        return self.v.size()

    def __repr__ (self):
        r = []
        for i, amt, script in self.val:
            r.append (str(i))
        return '<%s>' % (' '.join (r))

    property val:
        def __get__ (self):
            cdef outpoint o
            cdef list r = []
            for o in self.v:
                r.append ((o.index, o.amt, o.script))
            return r
        def __set__ (self, vals):
            cdef outpoint o
            cdef list r = []
            self.v.resize (len (vals))
            for i in range (len (vals)):
                (index, amt, script) = vals[i]
                self.v[i].index = index
                self.v[i].amt = amt
                self.v[i].script = script
    
    cdef get_output (self, index):
        cdef vector[outpoint].iterator i0
        cdef int j = 0
        i0 = self.v.begin()
        # XXX worth a binary search?
        while i0 != self.v.end():
            if deref(i0).index == index:
                return deref(i0).amt, deref(i0).script
            else:
                j += 1
            inc (i0)
        raise KeyError (index)

    cdef pop_utxo (self, int index, fist f):
        cdef outpoint_set m = outpoint_set([])
        cdef vector[outpoint].iterator i0
        cdef int j = 0
        m.v.resize (len(self.v) - 1)
        i0 = self.v.begin()
        while i0 != self.v.end():
            if deref(i0).index == index:
                f.amt = deref(i0).amt
                f.script = deref(i0).script
            else:
                m.v[j].index = deref(i0).index
                m.v[j].amt = deref(i0).amt
                m.v[j].script = deref(i0).script
                j += 1
            inc (i0)
        return m

cdef class aa_node:
    cdef readonly uint8_t level
    cdef readonly aa_node l, r
    cdef readonly char[32] k
    cdef readonly outpoint_set v

    def __cinit__ (self, int level, aa_node l, aa_node r):
        self.level = level
        self.l = l
        self.r = r

    property key:
        def __get__ (self):
            return self.k[:32]
        def __set__ (self, char * val):
            memcpy (self.k, val, 32)

    cdef aa_node copy (self):
        cdef aa_node n
        if self is tree_nil:
            return self
        else:
            return copy_node (self.level, self.l, self.r, self)

cdef aa_node copy_node (int level, aa_node l, aa_node r, aa_node other):
    cdef aa_node n = aa_node (level, l, r)
    memcpy (<char*>n.k, <char*>other.k, 32)
    n.v = other.v
    return n

cdef make_node (int level, aa_node l, aa_node r, char * key, object val):
    cdef aa_node node = aa_node (level, l, r)
    memcpy (<char*>node.k, <char*>key, 32)
    node.v = outpoint_set (val)
    return node

import sys
W = sys.stderr.write

cdef char ZERO[32]
# this global node acts as a sentinel
cdef aa_node tree_nil
tree_nil = aa_node (0, tree_nil, tree_nil)
tree_nil.l = tree_nil
tree_nil.r = tree_nil
tree_nil.v = outpoint_set ([])

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

cdef aa_node tree_insert (aa_node n, char * key, object val):
    cdef aa_node n0
    cdef int compare
    if n.level == 0:
        return make_node (1, tree_nil, tree_nil, key, val)
    else:
        compare = memcmp (n.k, key, 32)
        if compare > 0:
            n0 = copy_node (n.level, tree_insert (n.l, key, val), n.r, n)
        else:
            n0 = copy_node (n.level, n.l, tree_insert (n.r, key, val), n)
        return split (skew (n0))

# build a completish tree from sorted input
cdef aa_node tree_build (data_gen, int lo, int hi):
    cdef int mid = ((hi - lo) / 2) + lo
    cdef aa_node l, r
    if mid == hi == lo:
        return tree_nil
    else:
        l = tree_build (data_gen, lo, mid)
        txname, outputs = data_gen.next()
        r = tree_build (data_gen, mid + 1, hi)
        return make_node (l.level + 1, l, r, txname, outputs)

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

cdef aa_node tree_remove (fist self, aa_node root, char * key, int index):
    cdef aa_node root0
    cdef int compare
    # search down the tree
    if root is not tree_nil:
        self.heir = root
        compare = memcmp (root.k, key, 32)
        root0 = root.copy()
        if compare >= 0:
            self.item = root0
            root0.l = tree_remove (self, root0.l, key, index)
        else:
            root0.r = tree_remove (self, root0.r, key, index)
    else:
        root0 = root
    if root is self.heir:
        # at the bottom, remove
        if self.item is not tree_nil and memcmp (self.item.k, key, 32) == 0:
            self.item.v = self.item.v.pop_utxo (index, self)
            if len(self.item.v) == 0:
                # empty, remove it
                self.removed = True
                memcpy (self.item.k, self.heir.k, 32)
                self.item.v = self.heir.v
                self.item = tree_nil
                # here, we diverge from AA's paper, where he always return root0.r.
                if root0.r is tree_nil:
                    return root0.l
                else:
                    return root0.r
            else:
                # not empty yet, don't remove it
                return root0
        else:
            # KeyError?
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
        W ('%s%4d %r\n' % ('  ' * d, n.level, n.k[:32]))

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
                compare = memcmp (search.k, <char*>key, 32)
                if compare == 0:
                    return search
                elif compare < 0:
                    search = search.r
                else:
                    search = search.l

    def __contains__ (self, object key):
        cdef aa_node probe = self._search (key)
        return probe is not tree_nil

    def get_utxo (self, object name, int index):
        cdef aa_node probe = self._search (name)
        if probe is not tree_nil:
            return probe.v.get_output (index)
        else:
            raise KeyError (name)

    def __iter__ (self):
        # (<txname>, [(<index>, <amt>, <script>), ...])
        for node in walk (self.root):
            yield node.key, node.v.val

    def verify (self):
        verify (self.root)

    def dump (self, fout):
        for n, d in walk_depth (self.root, 0):
            fout.write ('%s%4d %r:%r\n' % ('  ' * d, n.level, n.key.encode('hex'), n.v))

    def new_entry (self, bytes txname, object vals):
        cdef aa_node new_root
        if len(vals) == 0:
            raise ValueError
        self.root = tree_insert (self.root, txname, vals)
        self.length += 1
        #assert (txname in self)

    def pop_utxo (self, bytes txname, int index):
        f = fist()
        #assert (txname in self)
        self.root = tree_remove (f, self.root, txname, index)
        if f.removed:
            self.length -= 1
        return f.amt, f.script

# -------------------------------------------------------------------
# This is a straightforward STL version of the map, used just for
# the initial scan.  It's much faster because it's non-persistent.
# -------------------------------------------------------------------

from libcpp.pair cimport pair
from libcpp.map cimport map
from libcpp.set cimport set

# XXX figure out why cython barfs at uint64_t here
#ctypedef pair [uint64_t, string] outpoint_val
ctypedef pair [long, string] outpoint_val
ctypedef map [uint16_t, outpoint_val] outpoint_map
ctypedef map [string, outpoint_map] utxo_map

cdef class UTXO_Scan_Map:

    cdef utxo_map m

    def __len__ (self):
        return self.m.size()

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
        cdef list item
        cdef int j
        i0 = self.m.begin()
        while i0 != self.m.end():
            i1 = deref(i0).second.begin()
            item = [None] * deref(i0).second.size()
            j = 0
            while i1 != deref (i0).second.end():
                index, (amt, script) = deref (i1)
                item[j] = (index, amt, script)
                inc (i1)
                j += 1
            yield (deref(i0).first, item)
            inc(i0)
