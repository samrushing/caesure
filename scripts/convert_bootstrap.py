# -*- Mode: Python -*-

# convert bootstrap.dat into caesure's format, in-place.
# XXX consider either
#  1) using the torrent version as-is
#  2) supporting both formats?
#  3) auto-converting upon first load?

# the bootstrap.dat file has this format:
# (<mainnet-magic> <32-bit size> <block data>)+
# caesure's format:
# (<64-bit size> <block data>)+

import struct
import sys

path = sys.argv[1]

f = open (path, 'r+')
while 1:
    pos = f.tell()
    magic = f.read (4)
    assert (magic == '\xf9\xbe\xb4\xd9')
    size, = struct.unpack ('<I', f.read (4))
    f.seek (pos)
    f.write (struct.pack ('<Q', size))
    f.seek (pos + 8 + size)
