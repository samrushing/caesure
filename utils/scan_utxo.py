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
            # this is followed by ((txname,index), [(index, amt, script), ...])
            yield df.read_object()
    except EOFError:
        f.close()
