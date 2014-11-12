
Caesure: a python bitcoin server/node
=====================================

name
----

It's a pun on the words Caesar and Seizure.  "Render unto Caesar..."

requirements
------------

  1. [shrapnel](https://github.com/ironport/shrapnel)
  2. [Cython](http://cython.org/)
  3. [secp256k1](https://github.com/bitcoin/secp256k1) (optional)

install
-------

    $ sudo python setup.py install
    $ mkdir /usr/local/caesure/

Make sure the /usr/local/caesure directory is writable by the user that will be running caesure.

To avoid a long startup time, fetch a copy of the blockchain and convert it.
[see below for instructions]

status
------

Handles incoming & outgoing connections, does parallel blockchain download.  Caches metadata for quick
startup.  Many-worlds ledger implementation nearly finished.

See TODO.txt for more detail on status.

design
------

Since this uses shrapnel, it leaves out Windows users, but still
allows bsd, darwin/osx, & linux.

The target platform is a well-connected machine (i.e., in a colocation
facility) with fast disk and lots of memory.  [As of October 2014, the
process size is approximately 3GB.  I would recommend at least 6GB of
memory, the more the merrier.]

Note: you should be using a 64-bit system.  Although it should be
possible to run most of the system in 32-bit mode, consider it an
unsupported configuration, because of the memory requirements.

Performance-sensitive code is written in Cython, including packet
codec, b58, hexify, etc...

The script engine is mostly done.  Needs some work on failing
constraints like stack size, sig count, etc.

The current plan is to have a pruning ledger in memory (with
journalling-style checkpoints to disk).  Without a ledger, this code
is not a full forwarding node, and thus by default the 'relay' flag in
the outgoing version packet is set to False.

See TODO.txt & ledger.py for details.

usage
-----

$ scripts/caesure -h::

    usage: caesure [-h] [-o OUTGOING] [-i INCOMING] [-s IP:PORT] [-c IP:PORT] [-m]
                   [-a] [-r] [-u USER:PASS] [-v]
    
    optional arguments:
      -h, --help            show this help message and exit
      -o OUTGOING, --outgoing OUTGOING
                            total number of outgoing connections
      -i INCOMING, --incoming INCOMING
                            total number of incoming connections
      -s IP:PORT, --serve IP:PORT
                            serve on this address
      -c IP:PORT, --connect IP:PORT
                            connect to this address
      -m, --monitor         run the monitor on /tmp/caesure.bd
      -a, --webui           run the web interface at http://localhost:8380/admin/
      -r, --relay           [hack] set relay=True
      -u USER:PASS, --user USER:PASS
                            webui user (will listen on INADDR_ANY)
      -v, --verbose         show verbose packet flow


Connecting to a local bitcoind::

    $ scripts/caesure -o 1 -i 0 -c 127.0.0.1:8333 -m -a

Start up a node with 20 outgoing connections and 0 incoming (i.e., no server)::

    $ scripts/caesure -o 20 -i 0 -c -m -a

Start up a node with 100 outgoing connections and 100 incoming::

    $ scripts/caesure -o 100 -i 100 -m -a -s 1.2.3.4:8333

Once up and running, caesure will start downloading the block chain from the network if necessary.

You can monitor its progress via the web ui:

    http://127.0.0.1:8380/admin/status

Or via the back door / monitor:

[from another terminal]

    $ telnet /tmp/caesure.bd

telnet to a unix socket is bsd only, on linux try:

    $ nc -CU /tmp/caesure.bd

you'll get a python prompt:

    >>> db = G.block_db
    >>> len(db.blocks)
    10123
    >>> 
    >>> len(db.blocks)
    18539
    >>> 
    >>> len(db.blocks)
    66029
    >>> 
    [...]

bootstrap.dat
-------------

I recommend that you download the blockchain bootstrap.dat file (via bit torrent), and use that as your starting point.
The format of the bootstrap.dat file is nearly identical to caesure's native format, and can be converted in-place::

    $ python scripts/convert_bootstrap.py bootstrap.dat
    $ mv bootstrap.dat /usr/local/caesure/blocks.bin

You should be able to find the torrent here: https://bitcoin.org/bin/blockchain/

testnet
-------

Testnet support is currently missing, it's not hard to add it back in if needed.

logging
-------

Caesure uses a binary (fast, machine-readable) logging system, using
the ASN1 capabilities of shrapnel.  In utils/catlog.py is a tool that
can be used for decoding/processing the logfile.  It can be combined
with "tail -f" to tail the logs, e.g.::

    $ cat /usr/local/caesure/log.asn1 | catlog | less
    $ tail -f /usr/local/caesure/log.asn1 | catlog | less

fun with the block chain
------------------------

Rather than running a client, you can just start up python and play
with the block database.  The block database is written in append-only
mode, so it's safe to open it read-only from another process, even
while the client is running.

$ python -i caesure/block_db.py::

      >>> db = BlockDB()
    reading metadata...done 5.62 secs (last_block=302294)
    reading block headers...starting at pos 19149083102...(302294)done. scanned 17 blocks in 0.00 secs
    >>> db.last_block
    302310
    >>> db.by_num(_)
    <__main__.BLOCK object at 0x800f090d0>
    >>> b = _
    >>> b.transactions[1]
    <__main__.TX object at 0x800e30fa0>
    >>> tx = _
    >>> tx.dump()
    hash: e8751d4130d77cdc3746dc6cce32e00f57b1abf9cef84104a5764cefc933f38b
    inputs: 2
      0 0c8c368d00fe30e30426d3759bbb0c0244242d53eb1935ab6ac9e6b7e39e5356:1 ['0x3045022100f0a0e4c2bfd414e8232ae98a4ba564d0040338e8a94e563d6ab599900e2c93dd022054b68c96da5ba2e68bc46a9b65cd230028aa66caa83d85be9e7d155838a44c7e01', '0x04bb8234d9fbc26ad8e9c328805f8ff77cc3857ac3875ad56c74203b93fffe33a868cb870841128c0ce43838929be16da0a369c683c3d2e7fc395e4a21ae6faf30'] 4294967295
      1 540cff744f98351c7c8459b85a52ca6ab3a6c2b9cdcaf8aec1e4ad2c58cae2df:0 ['0x304502203aca08e12b347d6056f88367434d6ac9fb097eb0d6b677e7987c2122f8d8989402210088cf9838a9ccbd0878b44c381aedb1b8c4e84deeda04964aa4e53e8d9e086c2801', '0x0455d41ff12fbe28a8112d3027f100a80fe16a877b69e9fc66062777ece4d2327c9b7607f056afd4b59014b42daab284e09b64f92fff498e068bcee41752c5e26d'] 4294967295
    2 outputs
      0 39.52026906 ['OP_DUP', 'OP_HASH160', '0x67a5b321d47682682249a4baa1cf53de4f6d2701', 'OP_EQUALVERIFY', 'OP_CHECKSIG']
      1 47.87863094 ['OP_DUP', 'OP_HASH160', '0x96a852c7f06db0d93e4bfac314b979976d1095cc', 'OP_EQUALVERIFY', 'OP_CHECKSIG']
    lock_time: 0
    >>> tx.inputs[0]
    ((<0c8c368d00fe30e30426d3759bbb0c0244242d53eb1935ab6ac9e6b7e39e5356>, 1), 'H0E\x02!\x00\xf0\xa0\xe4\xc2\xbf\xd4\x14\xe8#*\xe9\x8aK\xa5d\xd0\x04\x038\xe8\xa9NV=j\xb5\x99\x90\x0e,\x93\xdd\x02 T\xb6\x8c\x96\xda[\xa2\xe6\x8b\xc4j\x9be\xcd#\x00(\xaaf\xca\xa8=\x85\xbe\x9e}\x15X8\xa4L~\x01A\x04\xbb\x824\xd9\xfb\xc2j\xd8\xe9\xc3(\x80_\x8f\xf7|\xc3\x85z\xc3\x87Z\xd5lt ;\x93\xff\xfe3\xa8h\xcb\x87\x08A\x12\x8c\x0c\xe488\x92\x9b\xe1m\xa0\xa3i\xc6\x83\xc3\xd2\xe7\xfc9^J!\xaeo\xaf0', 4294967295)
    >>> parse_script (_[1])
    [(0, '0E\x02!\x00\xf0\xa0\xe4\xc2\xbf\xd4\x14\xe8#*\xe9\x8aK\xa5d\xd0\x04\x038\xe8\xa9NV=j\xb5\x99\x90\x0e,\x93\xdd\x02 T\xb6\x8c\x96\xda[\xa2\xe6\x8b\xc4j\x9be\xcd#\x00(\xaaf\xca\xa8=\x85\xbe\x9e}\x15X8\xa4L~\x01'), (0, '\x04\xbb\x824\xd9\xfb\xc2j\xd8\xe9\xc3(\x80_\x8f\xf7|\xc3\x85z\xc3\x87Z\xd5lt ;\x93\xff\xfe3\xa8h\xcb\x87\x08A\x12\x8c\x0c\xe488\x92\x9b\xe1m\xa0\xa3i\xc6\x83\xc3\xd2\xe7\xfc9^J!\xaeo\xaf0')]
    >>> pprint_script (_)
    ['0x3045022100f0a0e4c2bfd414e8232ae98a4ba564d0040338e8a94e563d6ab599900e2c93dd022054b68c96da5ba2e68bc46a9b65cd230028aa66caa83d85be9e7d155838a44c7e01', '0x04bb8234d9fbc26ad8e9c328805f8ff77cc3857ac3875ad56c74203b93fffe33a868cb870841128c0ce43838929be16da0a369c683c3d2e7fc395e4a21ae6faf30']
    >>> tx.outputs[0]
    (3952026906L, 'v\xa9\x14g\xa5\xb3!\xd4v\x82h"I\xa4\xba\xa1\xcfS\xdeOm\'\x01\x88\xac')
    >>> parse_script (_[1])
    [(2, 118), (2, 169), (0, 'g\xa5\xb3!\xd4v\x82h"I\xa4\xba\xa1\xcfS\xdeOm\'\x01'), (2, 136), (3, 172, 'v\xa9\x14g\xa5\xb3!\xd4v\x82h"I\xa4\xba\xa1\xcfS\xdeOm\'\x01\x88\xac')]
    >>> pprint_script (_)
    ['OP_DUP', 'OP_HASH160', '0x67a5b321d47682682249a4baa1cf53de4f6d2701', 'OP_EQUALVERIFY', 'OP_CHECKSIG']
    >>> 

fetch a block by number::

    >>> db.num_block[135000]
    set([<00000000000001bf349e3e8195f95a080ea17efe012cf7f512664829f9d3772d>])

    >>> db.by_num(135000)
    <__main__.BLOCK object at 0x800f090d0>

dump all its transactions::

    >>> for tx in b.transactions:
    ...     tx.dump()
    ... 

Note: you can also do all the above via the back door of a running caesure instance.

Your Support Appreciated: 1PDd8exMdhRTLAfNrjBQ9b8DYxkky3cFy1
------------------------------------------------------------
