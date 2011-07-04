# -*- Mode: Python -*-

# this will read an official-bitcoin-client "wallet.dat" file, and
#   try to find private keys.  It will then export them in the format
#   used by bitcoin.py.

import struct
import sys
data = open (sys.argv[1], 'rb').read()

# not necessary, but useful.
from pyasn1.codec.der import decoder

import bitcoin

# find private keys in a wallet.dat file

keys = []

pos = 0

while 1:
    pos = data.find ('0\x82\x01\x13\x02\x01\x01\x04', pos)
    if pos != -1:
        key = data[pos:pos+279]
        if key in keys:
            print 'duplicate?'
        else:
            keys.append (key)
        pos += 279
    else:
        break

print '%d keys' % (len(keys),)

file = open ('wallet.bin', 'wb')

for key in keys:
    try:
        # if the key decodes it's probably legit, right?
        decoder.decode (key)
        pub0 = key[-65:]
        pub1 = bitcoin.rhash (pub0)
        addr = bitcoin.key_to_address (pub1)
        file.write (struct.pack ('<Q', len(key)))
        file.write (key)
    except:
        print 'bad key?'

file.close()
    

