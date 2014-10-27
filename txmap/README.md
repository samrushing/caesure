
Transaction Map Server
======================

Requirements
------------
In addition to caesure's normal requirements, this needs the python leveldb module.

Plan
----
Use leveldb to keep an on-disk map of transaction -> block + index
have the server monitor blocks.bin for new blocks when they come in.
serve this up via asn1-rpc and/or jsonrpc.

This isn't useful to caesure directly, but would be a nice
 public service alongside bc.info, blockr, etc...

(I need it for finding test cases).

Status
------
The txmap object is written, no server yet.

Performance
-----------
Currently this uses caesure's BlockDB class to pull the entire block
up from disk and parse it.  This probably doesn't matter for now, but
if the server needs to handle a heavy load (i.e., if it goes public) I
might add code to scan directly to the wanted txn.  And add a
memoization layer.


Disk Usage
----------
As of late Oct 2014, the leveldb directory holding the data is ~1.4GB.
Only the first half (16 bytes) of the txname is stored in the
database, mapping to a (height, index) pair.


Kqueue
------
My plan now is to monitor the blocks.bin file for additions using kqueue, I think
linux has similar monitoring capabilities.  Until that's added you'll need to be
on *BSD or OSX.

Usage
-----
Using the txmap object directly::

    darth:txmap rushing$ lpython -i txmap.py
    reading metadata...done 2.80 secs (last_block=326848)
    reading block headers...starting at pos 25222924521...(326848)done. scanned 1 blocks in 0.00 secs
    >>> txmap['9a5de5a52b5c10003ca7955246e3bf07b2bbd4f042b8f77d9d5a5fa581d92ff8']
    (<000000000000000067ecc744b5ae34eebbde14d21ca4db51652e4d67e155f07e>, 299999, 7, <caesure.bitcoin.TX object at 0x102ec4de0>)
    >>> txmap['98f1c2c0fa5af068e5a1b486a815acd6458b71cda2daa7ec62d5ec6098e4e60d']
    (<000000000000000012bb6ff8c02b7e74cfa7e6597c5c238b37340af1db9f14a8>, 324141, 490, <caesure.bitcoin.TX object at 0x111064750>)
    >>>


