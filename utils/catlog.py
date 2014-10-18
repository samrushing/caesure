# -*- Mode: Python -*-

import struct
import sys
from coro.asn1.python import decode

class Sync:
    
    magic = '%\xf1\xbfB'
    def __init__ (self):
        self.state = 0
        self.last = None
    def feed (self, ch):
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

def unbiggen(ob):
    if type(ob) is bytes and len(ob) > 500:
        return '<large>'
    else:
        return ob

s = Sync()
while 1:
    ch = sys.stdin.read (1)
    if ch == '':
        raise EOFError
    else:
        if s.feed (ch):
            break

while 1:
    size, = struct.unpack ('>I', sys.stdin.read (4))
    block = sys.stdin.read (size)
    (timestamp, info), size = decode (block)
    info = [unbiggen(x) for x in info]
    print timestamp, info
    magic = sys.stdin.read (4)
    if not magic:
        break
    else:
        assert (magic == Sync.magic)
