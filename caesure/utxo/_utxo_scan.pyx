# -*- Mode: Python -*-

# -------------------------------------------------------------------
# This is a straightforward STL version of the map, used just for
# the initial scan.  It's much faster because it's non-persistent.
# -------------------------------------------------------------------

from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t
from libc.string cimport memcmp, memcpy

from libcpp.utility cimport pair
from libcpp.map cimport map
from libcpp.set cimport set
from libcpp.string cimport string
from cython.operator cimport dereference as deref, preincrement as inc

# Note: if you get an error here, you need to upgrade cython.
ctypedef pair [uint64_t, string] outpoint_t
ctypedef map [uint16_t, outpoint_t] index_map_t
ctypedef map [string, index_map_t] utxo_map_t

# this is only used for iteration over the outer map.
cdef class index_map:
    cdef public bytes txname
    cdef public list d

    def __init__ (self, name, d):
        self.txname = name
        self.d = d

    def __iter__ (self):
        for index, amt, oscript in self.d:
            yield index, amt, oscript

cdef class UTXO_Scan_Map:

    cdef utxo_map_t m

    def get_size (self):
        cdef uint32_t size0 = 0
        cdef uint32_t size1 = 0
        i0 = self.m.begin()
        while i0 != self.m.end():
            size0 += 1
            size1 += deref(i0).second.size()
            inc (i0)
        return size0, size1

    def load (self, gen, nitems):
        for txname, entries in gen:
            self.push (txname, entries)

    def push (self, bytes txname, object vals):
        cdef map[string, index_map_t].iterator i0
        cdef bytes script
        cdef uint64_t amt
        i0 = self.m.insert (
            pair[string, index_map_t](
                txname, index_map_t()
            )
        ).first
        for index, amt, script in vals:
            deref(i0).second[index] = (amt, script)

    def __contains__ (self, bytes txname):
        cdef map[string, index_map_t].iterator i0
        i0 = self.m.find (txname)
        return i0 != self.m.end()

    def pop (self, bytes txname, int index):
        cdef map[string, index_map_t].iterator i0
        cdef map[uint16_t, outpoint_t].iterator i1
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
        # we can't use the obvious builtin iteration here because it
        #  maps to a python dictionary which is not sorted.
        cdef index_map im
        cdef map[string, index_map_t].iterator i0
        cdef map[uint16_t, outpoint_t].iterator i1
        cdef uint32_t i = 0
        i0 = self.m.begin()
        while i0 != self.m.end():
            i1 = deref (i0).second.begin()
            v = [None] * deref(i0).second.size()
            i = 0
            while i1 != deref (i0).second.end():
                index = deref(i1).first
                amt, oscript = deref(i1).second
                v[i] = (index, amt, oscript)
                inc (i1)
                i += 1
            yield index_map (deref(i0).first, v)
            inc (i0)

