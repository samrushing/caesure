# -*- Mode: Cython; indent-tabs-mode:nil -*-
# distutils: language = c++

from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t
from libc.string cimport memcmp, memcpy

from libcpp cimport bool
from libcpp.string cimport string
from cython.operator cimport dereference as deref, preincrement as inc

import sys

W = sys.stderr.write

# in this version, we use two levels of FAA: the outermost level stores
#  by txname, and at each leaf we store another FAA by index.

cdef extern from "utxo.h" nogil:
    cdef cppclass FAA[T,C]:
        cppclass iterator:
            iterator()
            iterator operator++()
            bint operator==(iterator)
            bint operator!=(iterator)
            T& operator*()
            void dump_path()
            unsigned depth()
        iterator begin()
        iterator end()
        iterator find (T & x)
        FAA[T,C] insert (T val)
        FAA[T,C] remove (T val, bool & found, T & removed)
        FAA[T,C] verify()
        FAA()
        FAA (T*(*next)(), unsigned int lo, unsigned int hi)
        FAA[T,C] replace (iterator leaf, T & val)
        uint32_t size()
        bool is_empty()
        dump()
    cdef struct outpoint_t:
        uint16_t index
        uint64_t amt
        string oscript
        outpoint_t (uint16_t, uint64_t, string)
    cdef struct compare_outpoint_t
    ctypedef FAA[outpoint_t, compare_outpoint_t] index_map_t
    ctypedef uint8_t hash_t[32]
    cdef struct txname_t:
        hash_t name
        index_map_t outpoints
    cdef struct compare_txname_t
    ctypedef FAA[txname_t, compare_txname_t] txname_map_t

# this is only used for iteration over the outer map.
cdef class index_map:
    cdef public bytes txname
    cdef index_map_t m
    cdef public unsigned depth

    def __iter__ (self):
        cdef outpoint_t item
        for item in self.m:
            yield item.index, item.amt, item.oscript

    def __len__ (self):
        return self.m.size()

    def __repr__ (self):
        cdef outpoint_t item
        r = []
        for item in self.m:
            r.append (str (item.index))
        return '<index_map %s at 0x%x>' % (' '.join (r), id(self))

cdef class UTXO_Map:
    cdef txname_map_t m
    # total number of unique txnames
    cdef uint32_t size0
    # total number of outpoints
    cdef uint32_t size1

    def __init__ (self):
        self.size0 = 0
        self.size1 = 0

    def get_size (self):
        return self.size0, self.size1

    def copy (self):
        r = UTXO_Map()
        r.m = self.m
        r.size0 = self.size0
        r.size1 = self.size1
        return r

    def push (self, bytes txname, outpoints):
        cdef txname_t txname_entry
        cdef uint16_t index
        cdef uint64_t amt
        cdef bytes oscript
        cdef outpoint_t outpoint_entry
        cdef txname_map_t new_root

        memcpy (txname_entry.name, <char*>txname, len(txname))
        for index, amt, oscript in outpoints:
            outpoint_entry.index = index
            outpoint_entry.amt = amt
            outpoint_entry.oscript = oscript
            txname_entry.outpoints = txname_entry.outpoints.insert (outpoint_entry)
        self.m = self.m.insert (txname_entry)
        self.size0 += 1
        self.size1 += len(outpoints)

    def pop (self, bytes txname, uint16_t index):
        cdef bool found = False
        cdef txname_t out0
        cdef txname_t out2
        cdef outpoint_t out1
        cdef txname_map_t m0
        cdef txname_map_t m1
        memcpy (out0.name, <char*>txname, 32)
        probe0 = self.m.find (out0)
        if probe0 == self.m.end():
            raise KeyError ((txname, index))
        else:
            out1.index = index
            memcpy (out2.name, <char*>txname, 32)
            out2.outpoints = deref(probe0).outpoints.remove (out1, found, out1)
            if found:
                if out2.outpoints.is_empty():
                    self.m = self.m.remove (out0, found, out0)
                    self.size0 -= 1
                else:
                    self.m = self.m.replace (probe0, out2)
                self.size1 -= 1
                return out1.amt, out1.oscript
            else:
                raise KeyError ((txname, index))

    def __contains__ (self, bytes txname):
        cdef txname_t key
        memcpy (key.name, <char*>txname, 32)
        return not self.m.find (key) == self.m.end()

    def get (self, bytes txname, uint16_t index):
        cdef bool found = False
        cdef txname_t out0
        cdef outpoint_t out1
        memcpy (out0.name, <char*>txname, 32)
        probe0 = self.m.find (out0)
        if probe0 == self.m.end():
            raise KeyError ((txname, index))
        else:
            out1.index = index
            probe1 = deref(probe0).outpoints.find (out1)
            if probe1 == deref(probe0).outpoints.end():
                raise KeyError ((txname, index))
            else:
                return deref(probe1).amt, deref(probe1).oscript

    def get_tx (self, bytes txname):
        cdef bool found = False
        cdef txname_t out0
        cdef index_map im
        memcpy (out0.name, <char*>txname, 32)
        probe0 = self.m.find (out0)
        if probe0 == self.m.end():
            raise KeyError (txname)
        else:
            im = index_map()
            im.m = deref(probe0).outpoints
            return im

    def __iter__ (self):
        cdef txname_t item0
        cdef index_map im
        i0 = self.m.begin()
        while i0 != self.m.end():
            im = index_map()
            im.txname = deref(i0).name[:32]
            im.m = deref(i0).outpoints
            im.depth = i0.depth()
            inc (i0)
            yield im

    def verify (self):
        self.m.verify()

    def load (self, gen, nitems):
        global pop0_gen, size0, size1
        pop0_gen = gen
        self.m = txname_map_t (&next_txname_fun, 0, nitems)
        self.size0 = size0
        self.size1 = size1

cdef index_map_t get_tx (txname_map_t m, bytes txname):
    cdef bool found = False
    cdef txname_t out0
    cdef index_map im
    memcpy (out0.name, <char*>txname, 32)
    probe0 = m.find (out0)
    if probe0 == m.end():
        raise KeyError (txname)
    else:
        return deref(probe0).outpoints

# --------------------------------------------------------------------------------
# this code is used to load the data structure into memory as quickly as possible,
#  assuming all the inputs are sorted.  I don't like using these globals, but I can't
#  find an easier way to feed the build() functions data one piece at a time...

cdef object pop0_gen
cdef object pop1_gen
cdef txname_t pop0_item
cdef outpoint_t pop1_item
cdef uint32_t size0 = 0
cdef uint32_t size1 = 0

def listgen(y):
    for x in y:
        yield x

cdef txname_t* next_txname_fun() with gil:
    global pop0_item, pop1_gen, size0, size1
    cdef outpoint_t outpoint_entry
    txname, entries = pop0_gen.next()
    memcpy (pop0_item.name, <char*>txname, len(txname))
    pop1_gen = listgen (entries)
    pop0_item.outpoints = index_map_t (&next_outpoint_fun, 0, len(entries))
    size0 += 1
    size1 += len(entries)
    return &pop0_item

cdef outpoint_t* next_outpoint_fun() with gil:
    global pop1_item
    pop1_item.index, pop1_item.amt, pop1_item.oscript = pop1_gen.next()
    return &pop1_item
