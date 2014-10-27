#!/usr/bin/env python
# -*- Mode: Python -*-

import argparse
import struct
import sys
import time
from coro.asn1.python import decode

class Sync:
    
    magic = '%\xf1\xbfB'
    def __init__ (self):
        self.state = 0
        self.last = None
    def feed (self, ch):
        #sys.stderr.write ('[%d ch=%r]' % (self.state, ch))
        if ch == self.magic[self.state]:
            self.state += 1
            if self.state == 4:
                return True
            else:
                return False
        else:
            self.state = 0
            self.last = ch
            return False
    def resync (self, fdin):
        sys.stderr.write ('resync...')
        self.state = 0
        while 1:
            ch = fdin.read (1)
            if ch == '':
                raise EOFError
            else:
                if self.feed (ch):
                    break

def is_binary (ob):
    if type(ob) is not bytes:
        return False
    else:
        for ch in ob[:20]:
            if ord(ch) & 0x80:
                return True

# note: this is application-specific - remove before putting this file into shrapnel.
def frob(ob):
    if type(ob) is bytes:
        if is_binary (ob):
            if args.big_hex:
                return ob.encode ('hex')
            elif args.big:
                return ob
            else:
                return '<large>'
        elif len(ob) == 32:
            return ob[::-1].encode ('hex')
        return ob
    else:
        return ob

def main():
    global args
    p = argparse.ArgumentParser()
    p.add_argument ('-b', '--big', action='store_true', help="show large strings", default=False)
    p.add_argument ('-bh', '--big-hex', action='store_true', help="show large strings in hex", default=False)
    p.add_argument ('-nb', '--no_blocks', action='store_true', help="elide 'block' packets", default=False)
    p.add_argument ('file', help="input file", nargs="?", metavar="FILE")
    args = p.parse_args()

    if args.file is None:
        file = sys.stdin
    else:
        file = open (args.file, 'rb')

    s = Sync()

    s.resync (file)

    while 1:
        size, = struct.unpack ('>I', file.read (4))
        block = file.read (size)
        if len(block) != size:
            break
        (timestamp, info), size = decode (block)
        timestamp /= 1000000.0
        if args.no_blocks and len(info) > 3 and info[2] == 'block':
            pass
        else:
            info = [frob(x) for x in info]
            print time.ctime (timestamp), info
        magic = file.read (4)
        if not magic:
            break
        elif magic != Sync.magic:
            s.resync (file)

if __name__ == '__main__':
    main()
