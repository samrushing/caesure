# -*- Mode: Python -*-

from coro.asn1.data_file import DataFileReader

def gen_utxo (path='/usr/local/caesure/utxo.bin'):
    f = open (path, 'rb')
    df = DataFileReader (f)
    info = df.read_object()
    # note: first object is some metadata
    [version, height, block_name, total, lost, fees, size] = info
    try:
        while 1:
            # this is followed by (txname[:16], index, amt, script), ...
            yield df.read_object()
    except EOFError:
        f.close()


if __name__ == '__main__':
    import argparse
    import os
    p = argparse.ArgumentParser (description='scan utxo db')
    p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
    args = p.parse_args()

    import sys
    from collections import Counter

    h = Counter()
    W = sys.stderr.write
    i = 0
    month = 30 * 24 * 60 * 60
    for item in gen_utxo (os.path.join (args.base, 'utxo.bin')):
        key, amt, oscript = item
        import struct
        timestamp, = struct.unpack ('>L', oscript[:4])
        print key.encode ('hex'), oscript[4:].encode ('hex')
        bucket, _ = divmod (timestamp, month)
        h[bucket] += 1
        if i % 10000 == 0:
            W ('.')
        i += 1
    W ('\ntotal: %d entries\n' % (i,))
