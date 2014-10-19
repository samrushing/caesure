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
        sys.stderr.write ('[%d ch=%r]' % (self.state, ch))
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

# note: this is application-specific - remove before putting this file into shrapnel.
def frob(ob):
    if type(ob) is bytes:
        if len(ob) > 500:
            return '<large>'
        elif len(ob) == 32:
            return ob[::-1].encode ('hex')
        return ob
    else:
        return ob

s = Sync()
s.resync (sys.stdin)

while 1:
    size, = struct.unpack ('>I', sys.stdin.read (4))
    block = sys.stdin.read (size)
    (timestamp, info), size = decode (block)
    info = [frob(x) for x in info]
    print timestamp, info
    magic = sys.stdin.read (4)
    if not magic:
        break
    elif magic != Sync.magic:
        s.resync (sys.stdin)
