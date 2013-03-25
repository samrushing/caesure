
Caesure: a python bitcoin server/node
=====================================

Your Support Appreciated: 1Ncui8YjT7JJD91tkf42dijPnqywbupf7w
------------------------------------------------------------

requirements
------------

  1. [shrapnel](https://github.com/ironport/shrapnel)
  2. either 

    * an openssl library or
    * the pure-python ecdsa package

name
----

It's a pun on the words Caesar and Seizure.  "Render unto Caesar..."

[I realize now that the pun doesn't work in Latin, where Caesar is pronounced 'Kaiser'.  Sorry.]

status
------

In the midst of being ported to shrapnel.  This leaves out Windows users, but still
allows bsd, darwin/osx, & linux.

In addition to the port to shrapnel, some performance-sensitive code is being moved
to cython, including packet codec, b58, hexify, etc...

I'm attempting to make this a full node, with tx verification etc....

Script engine is mostly done.  Needs some work on failing constraints
like stack size, sig count, etc.

For the outpoint database, I'm playing with leveldb.  While verifying
the entire blockchain, it seems to perform well at first, but then
disk i/o becomes a serious bottleneck.  For now I'm building the
outpoint db in memory.


usage
-----

    $ python bitcoin.py -c <your-external-ip-address> <other-ip-address>

I recommend connecting to a bitcoin client on your local machine, i.e., 127.0.0.1.

Once the client connects to the server it will start to download the block
database.  This will take a while, even if you're talking to localhost.

You can monitor the progress like this:

from another terminal:

    $ telnet /tmp/caesure.bd

[telnet to a unix sock is bsd only, try netcat on linux or bind to 127.0.0.1]

you'll get a python prompt:

    >>> the_block_db
    <__main__.block_db instance at 0x43bdc8>
    >>> db = _
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


web admin
---------

With '-a', a web UI is brought up on localhost:
try http://localhost:8380/admin/ (note: that trailing slash is important)

*** This is getting more useful, try it! ***


testnet
-------

To use testnet, give the '-t' argument along with '-c'.  This will change several
global values, and should NOT impact your block database - it uses different
filenames.

paper keys
----------

I've included a simple utility for generating paper keys.  It will generate a set
of fresh keys and send them to stdout with the private keys in 'wallet import format'.
On my Mac, I do this...

    $ python paper_keys.py 5 | lpr

... to send them directly to the printer.

fun with the block chain
------------------------

Rather than running a client, you can just start up python and play
with the block database.  The block database is written in append-only
mode, so it's safe to open it read-only from another process, even
while the client is running.

    $ python -i bitcoin.py
    reading block headers...
    last block (135225): 0000000000000478bd4859949e91b44cc28e6a02e7bb2985df250751063e1d1f
    >>> db['0000000000000478bd4859949e91b44cc28e6a02e7bb2985df250751063e1d1f']
    <__main__.BLOCK instance at 0x3e7d508>
    >>> b = _
    >>> b.transactions[1]
    <__main__.TX instance at 0x1e9508>
    >>> tx = _
    >>> tx
    <__main__.TX instance at 0x1e9508>
    
    dump a transaction:
    >>> tx.dump()
    hash: b1f8edbda61061be661731d3de215299f1356736502e52a0772a9259f7fd699d
    inputs: 1
      0 13f23ebb1643b6faa02cf93f0bfd5c97c22bd76f3e9464ec61601d84f3afd404:0 493046022100b64136b383721bede39c6ff855339920928006c43d5f536d45c14ab401b736f8022100ee564e42001e3b071545e5f55bbcaa87eca7d731a339177701c40fa6d61510bf014104b3cd4b6d65ffea8fb7781e88a4e67d2f8104b80fb45ee50981940001d3a132584ea10a34a03224823492fd25344c50e40a52069df297da024ffb3175ec745021 4294967295
    2 outputs
      0 30.00000000 142rU1TWaxZkrTbxvvLGY8VyKiEyYPtKZu
      1 10.00000000 1Q9vpsULCLxS7dLXGg9kcfG31DTTqnhoxy
    lock_time: 0
    >>>

fetch a block by number:

    >>> db.num_block[135000]
    '00000000000001bf349e3e8195f95a080ea17efe012cf7f512664829f9d3772d'
    >>> b = db[_]

dump all its transactions:

    >>> for tx in b.transactions:
    ...     tx.dump()
    ... 

### verify a transaction ###

verify the first input of a transaction:

    >>> tx.verify (0)
    1


