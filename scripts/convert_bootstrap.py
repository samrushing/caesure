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
import argparse

W = sys.stderr.write

def main (args):
    f = open (args.file, 'r+')
    n = 0
    while 1:
        n += 1
        if n % 1000 == 0:
            W ('[%d]' % (n,))
        pos = f.tell()
        magic_size = f.read (8)
        magic = magic_size[:4]
        size = magic_size[4:]
        if magic == '':
            break
        else:
            assert (magic == '\xf9\xbe\xb4\xd9')
            size, = struct.unpack ('<I', size)
            f.seek (pos)
            f.write (struct.pack ('<Q', size))
            f.seek (pos + 8 + size)
    W ('...done.\n')
        
if __name__ == '__main__':
    p = argparse.ArgumentParser (description="bootstrap.dat -> caesure in-place format converter.")
    p.add_argument ('file', help="file in bootstrap.dat format")
    args = p.parse_args()
    main (args)
